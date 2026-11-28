from base64 import b64encode, b64decode
from datetime import datetime
from getpass import getpass
import json

from secure_messaging.business.signing.signers import RsaSigner, EcdsaSigner
from secure_messaging.entities.identity import DigitalSignature
from secure_messaging.entities.cipher_type import CipherType
from secure_messaging.infrastructure.exceptions import CryptoException
from secure_messaging.services.cipher_factory import CipherFactory


class ConsoleMenu:
    def __init__(self, messenger, keys, logger, user, config):
        self._messenger, self._keys, self._logger = messenger, keys, logger
        self._user, self._config = user, config

    def generate(self):
        algorithm = input("RSA / ECC: ").strip().upper()
        pair = self._keys.generate(self._user.name, algorithm,
                                   self._config.get("key_size") if algorithm == "RSA" else None)
        try:
            self._keys.save(self._user.name, pair)
        finally:
            pair.private.wipe()
        print("Đã lưu khóa.")

    def public_key(self):
        print(b64encode(self._keys.get(input("Chủ khóa: ")).public.export()).decode())

    def _select_cipher(self):
        kind = CipherType(input("AES / RSA / ECC / CHACHA20: ").strip().upper())
        if kind in CipherFactory.supported_symmetric():
            cipher = CipherFactory.create_symmetric(kind, bytes.fromhex(getpass("Khóa dạng hex: ")))
        else:
            pair = self._keys.ensure_usable(input("Chủ khóa: "))
            cipher = CipherFactory.create_asymmetric(kind, pair)
        self._messenger.set_cipher(cipher)

    def handle_encrypt(self):
        self._select_cipher()
        print(b64encode(self._messenger.send(input("Bản rõ: ").encode())).decode())

    def handle_decrypt(self):
        self._select_cipher()
        print(self._messenger.receive(b64decode(input("Bản mã Base64: "), validate=True)).decode())

    def handle_sign(self):
        public = self._keys.get(self._user.name).public
        self._messenger.set_signer(RsaSigner() if public.algorithm == "RSA" else EcdsaSigner())
        sig = self._messenger.sign(input("Văn bản: ").encode(), self._user.name)
        print(json.dumps(dict(value=sig.to_base64(), signer_id=sig.signer_id,
                              algorithm=sig.algorithm, created_at=sig.created_at.isoformat())))

    def handle_verify(self):
        data = input("Văn bản: ").encode()
        raw = json.loads(input("Chữ ký JSON: "))
        sig = DigitalSignature(b64decode(raw["value"], validate=True), raw["signer_id"],
                               raw["algorithm"], datetime.fromisoformat(raw["created_at"]))
        public = self._keys.get(sig.signer_id).public
        self._messenger.set_signer(RsaSigner() if public.algorithm == "RSA" else EcdsaSigner())
        print("Hợp lệ" if self._messenger.verify(data, sig, public) else "Không hợp lệ")

    def revoke_key(self):
        self._keys.revoke(input("Chủ khóa: "), self._user)
        print("Đã thu hồi.")

    def view_log(self):
        print(*self._logger.read_all(self._user), sep="\n")

    def run(self):
        actions = {"1": ("Sinh và lưu khóa", self.generate), "2": ("Tải khóa công khai", self.public_key),
                   "3": ("Mã hóa", self.handle_encrypt), "4": ("Giải mã", self.handle_decrypt),
                   "5": ("Ký số", self.handle_sign), "6": ("Xác minh", self.handle_verify)}
        if self._user.is_admin():
            actions.update({"7": ("Thu hồi", self.revoke_key), "8": ("Xem nhật ký", self.view_log)})
        while True:
            print(" | ".join(f"{key}. {label}" for key, (label, _) in actions.items()), "| 0. Thoát")
            choice = input("> ").strip()
            if choice == "0":
                return
            try:
                actions[choice][1]()
            except (CryptoException, PermissionError, ValueError, KeyError, TypeError) as exc:
                print("Thao tác thất bại:", exc if isinstance(exc, (CryptoException, PermissionError)) else "Dữ liệu không hợp lệ")
