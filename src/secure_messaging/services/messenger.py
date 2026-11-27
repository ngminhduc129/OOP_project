from datetime import datetime, timezone
from secure_messaging.entities.identity import DigitalSignature
from secure_messaging.business.signing.signers import HashService
from secure_messaging.infrastructure.exceptions import CryptoException


class SecureMessenger:
    def __init__(self, keys, user):
        self._keys, self._user = keys, user
        self._observers = []
        self._cipher = self._signer = None

    def subscribe(self, callback):
        self._observers.append(callback)

    def set_cipher(self, cipher):
        self._cipher = cipher

    def set_signer(self, signer):
        self._signer = signer

    def _operation(self, action, algorithm, perform):
        result = "error"
        try:
            value = perform()
            result = "invalid" if value is False else "ok"
            return value
        finally:
            event = dict(time=datetime.now(timezone.utc).isoformat(), user=self._user.name,
                         action=action, algorithm=algorithm, result=result)
            for observe in self._observers:
                observe(event.copy())

    def send(self, data):
        if self._cipher is None:
            raise CryptoException("Select a cipher")
        return self._operation("encrypt", self._cipher.cipher_type.value, lambda: self._cipher.encrypt(data))

    def receive(self, data):
        if self._cipher is None:
            raise CryptoException("Select a cipher")
        return self._operation("decrypt", self._cipher.cipher_type.value, lambda: self._cipher.decrypt(data))

    def sign(self, data, owner, algorithm=None):
        signer = self._signer
        if signer is None or algorithm not in (None, signer.algorithm):
            raise CryptoException("Select the matching signer")
        def perform():
            pair = self._keys.ensure_usable(owner)
            value = signer.sign(HashService.sha256(data), pair.private)
            return DigitalSignature(value, owner, signer.algorithm, datetime.now(timezone.utc))
        return self._operation("sign", signer.algorithm, perform)

    def verify(self, data, signature, public):
        signer = self._signer
        if signer is None:
            raise CryptoException("Select a signer")
        return self._operation("verify", signer.algorithm, lambda: signature.algorithm == signer.algorithm
                               and signer.verify(HashService.sha256(data), signature.value, public))

