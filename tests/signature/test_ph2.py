import json
from datetime import datetime, timedelta, timezone
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from secure_messaging.business.signing.signers import HashService, EcdsaSigner, RsaSigner
from secure_messaging.entities.keys import KeyPair
from secure_messaging.entities.identity import User
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException
from secure_messaging.infrastructure.key_errors import KeyExpiredException, KeyRevokedException
from secure_messaging.infrastructure.repositories import FileKeyRepository, InMemoryKeyRepository
from secure_messaging.services.audit import AuditLogger
from secure_messaging.services.cipher_factory import CipherFactory
from secure_messaging.services.config import AppConfig
from secure_messaging.services.key_service import KeyService
from secure_messaging.services.messenger import SecureMessenger


@pytest.fixture
def keys():
    return KeyService(InMemoryKeyRepository())


@pytest.fixture
def ecc(keys):
    return keys.generate("alice", "ECC")


@pytest.fixture(scope="module")
def rsa():
    return KeyService(InMemoryKeyRepository()).generate("alice", "RSA")


def test_tc14_private(ecc):
    assert not hasattr(ecc.private, "export")
    assert b"ENCRYPTED PRIVATE KEY" in ecc.private.export_encrypted(b"pw-test")
    ecc.private.wipe()
    with pytest.raises(CryptoException):
        ecc.private._get_material()


def test_tc15_storage(tmp_path, ecc):
    repo = FileKeyRepository(tmp_path, lambda: b"pw-test")
    repo.save("alice", ecc)
    assert repo.load("alice").public.export() == ecc.public.export()
    assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in (tmp_path / "keys.sqlite3").read_bytes()


def test_tc16_revoke(tmp_path, ecc):
    repo = FileKeyRepository(tmp_path, lambda: b"pw-test")
    repo.save("alice", ecc)
    repo.revoke("alice")
    assert FileKeyRepository(tmp_path, lambda: b"pw-test").is_revoked("alice")


def test_tc17_rsa(rsa):
    digest = HashService.sha256(b"message")
    signer = RsaSigner()
    assert signer.verify(digest, signer.sign(digest, rsa.private), rsa.public)


def test_tc18_tamper(rsa):
    signer = RsaSigner()
    signature = signer.sign(HashService.sha256(b"message"), rsa.private)
    assert not signer.verify(HashService.sha256(b"messagE"), signature, rsa.public)


def test_tc19_wrong_key(keys, rsa):
    signer = RsaSigner()
    digest = HashService.sha256(b"message")
    assert not signer.verify(digest, signer.sign(digest, rsa.private), keys.generate("bob", "RSA").public)


def test_tc20_ecdsa(ecc):
    signer = EcdsaSigner()
    digest = HashService.sha256(b"message")
    assert signer.verify(digest, signer.sign(digest, ecc.private), ecc.public)


def test_tc21_deterministic(ecc):
    digest = HashService.sha256(b"message")
    signer = EcdsaSigner()
    first = signer.sign(digest, ecc.private)
    assert first == signer.sign(digest, ecc.private)
    assert signer.verify(digest, first, ecc.public)


def test_tc22_revoked(keys, ecc):
    keys.save("alice", ecc)
    keys.revoke("alice", User("staff", "admin"))
    messenger = SecureMessenger(keys, User("alice"))
    messenger.set_signer(EcdsaSigner())
    with pytest.raises(KeyRevokedException):
        messenger.sign(b"message", "alice")


def test_tc23_audit(tmp_path, keys):
    messenger = SecureMessenger(keys, User("alice"))
    audit = AuditLogger(tmp_path / "audit")
    audit.subscribe(messenger)
    messenger.set_cipher(CipherFactory.create_symmetric(CipherType.AES, b"x"*32))
    messenger.send(b"sensitive message")
    line, = audit.read_all(User("staff", "admin"))
    assert "sensitive message" not in line
    record = json.loads(line)
    assert set(record) == {"time", "user", "action", "algorithm", "result"}
    assert (record["action"], record["result"]) == ("encrypt", "ok")


def test_tc24_auth(keys, ecc):
    keys.save("alice", ecc)
    with pytest.raises(PermissionError):
        keys.revoke("alice", User("alice"))
    assert keys.ensure_usable("alice").public.export() == ecc.public.export()


def test_tc25_defaults(tmp_path):
    assert AppConfig(tmp_path / "missing").load().get("key_size") == 2048


def test_tc26_sha():
    assert HashService.sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_tc28_expiry(keys):
    past = datetime.now(timezone.utc) - timedelta(days=2)
    pair = KeyPair.from_private(ec.generate_private_key(ec.SECP256R1()), past, past + timedelta(days=1))
    keys.save("alice", pair)
    messenger = SecureMessenger(keys, User("alice"))
    messenger.set_signer(EcdsaSigner())
    with pytest.raises(KeyExpiredException):
        messenger.sign(b"message", "alice")


def test_tc29_size(keys, rsa):
    assert rsa.public.bits == 2048
    assert rsa.private._get_material().public_key().public_numbers().e == 65537
    with pytest.raises(CryptoException):
        keys.generate("bob", "RSA", 1024)


def test_tc30_log_access(tmp_path):
    with pytest.raises(PermissionError):
        AuditLogger(tmp_path / "audit").read_all(User("alice"))


def test_tc31_wrong_password(tmp_path, ecc):
    FileKeyRepository(tmp_path, lambda: b"pw-test").save("alice", ecc)
    with pytest.raises(CryptoException):
        FileKeyRepository(tmp_path, lambda: b"wrong").load("alice")


@pytest.mark.parametrize("contents", ["{broken", '{"key_size":512}'])
def test_tc34_bad_config(tmp_path, contents):
    path = tmp_path / "settings.json"
    path.write_text(contents)
    with pytest.raises(CryptoException):
        AppConfig(path).load()


@pytest.mark.parametrize("algorithm,signer", [("RSA", RsaSigner()), ("ECC", EcdsaSigner())])
def test_integrated_flow(tmp_path, algorithm, signer):
    keys = KeyService(FileKeyRepository(tmp_path, lambda: b"pw-test"))
    keys.save("alice", keys.generate("alice", algorithm))
    pair = keys.ensure_usable("alice")
    msg = SecureMessenger(keys, User("alice"))
    msg.set_cipher(CipherFactory.create_asymmetric(CipherType(algorithm), pair))
    original = b"integration"
    assert msg.receive(msg.send(original)) == original
    msg.set_signer(signer)
    signature = msg.sign(original, "alice")
    assert msg.verify(original, signature, pair.public)
    keys.revoke("alice", User("staff", "admin"))
    with pytest.raises(KeyRevokedException):
        msg.sign(original, "alice")
