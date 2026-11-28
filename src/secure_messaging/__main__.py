from getpass import getpass, getuser
from secure_messaging.entities.identity import User
from secure_messaging.infrastructure.repositories import FileKeyRepository
from secure_messaging.infrastructure.exceptions import CryptoException
from secure_messaging.services.audit import AuditLogger
from secure_messaging.services.config import AppConfig
from secure_messaging.services.key_service import KeyService
from secure_messaging.services.messenger import SecureMessenger
from secure_messaging.ui.console import ConsoleMenu


def main():
    try:
        config = AppConfig().load()
        name = getuser()
        user = User(name, "admin" if name in config.get("admins") else "user")
        repo = FileKeyRepository(config.get("key_dir"),
                                 lambda: getpass("Mật khẩu kho khóa: ").encode())
        keys = KeyService(repo)
        messenger = SecureMessenger(keys, user)
        audit = AuditLogger(config.get("audit_path"))
        audit.subscribe(messenger)
        ConsoleMenu(messenger, keys, audit, user, config).run()
    except CryptoException as exc:
        raise SystemExit(str(exc)) from exc
    except (KeyboardInterrupt, EOFError):
        return


if __name__ == "__main__":
    main()
