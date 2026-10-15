"""
Лабораторна робота №2
Завдання №1. Модель користувача та облікового запису.

Виконала: Данилович Анастасія
Група: КБ-201
Варіант: 5
"""

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

PBKDF2_ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


class User:
    """Клас користувача системи."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
    ) -> None:

        self.username = username
        self.role = role
        self.active = active

        self._email = ""
        self.email = email

        self.__password_hash = None
        self.__password_salt = None

    @property
    def email(self) -> str:
        """Отримання електронної адреси."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        """Перевірка електронної адреси."""

        if not EMAIL_REGEX.fullmatch(value):
            raise ValueError(f"Некоректний формат email: {value}")

        self._email = value

    def set_password(self, password: str) -> None:
        """Створення хешу пароля."""

        self.__password_salt = os.urandom(16)

        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Перевірка пароля."""

        if self.__password_hash is None or self.__password_salt is None:
            return False

        entered_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

        return hmac.compare_digest(
            self.__password_hash,
            entered_hash,
        )

    def deactivate(self) -> None:
        """Деактивація користувача."""
        self.active = False

    def __str__(self) -> str:
        """Інформація про користувача."""

        return (
            f"User(username='{self.username}', "
            f"email='{self.email}', "
            f"role='{self.role}', "
            f"active={self.active})"
        )


class Admin(User):
    """Клас адміністратора."""

    def __init__(
        self,
        username: str,
        email: str,
        permissions=None,
        active: bool = True,
    ) -> None:

        super().__init__(
            username=username,
            email=email,
            role="admin",
            active=active,
        )

        self.permissions = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        """Додавання права."""
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Видалення права."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевірка права."""
        return permission in self.permissions

    def __str__(self) -> str:
        """Інформація про адміністратора."""

        return (
            f"Admin(username='{self.username}', permissions={sorted(self.permissions)})"
        )


class Session:
    """Клас керування сеансом користувача."""

    def __init__(
        self,
        ip: str,
        login_time=None,
        last_activity=None,
    ) -> None:

        self.ip = ip

        self.login_time = login_time if login_time is not None else datetime.now(UTC)

        self.last_activity = (
            last_activity if last_activity is not None else self.login_time
        )

    def touch(self) -> None:
        """Оновлення часу активності."""

        self.last_activity = datetime.now(UTC)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевірка активності сеансу."""

        if timeout_sec <= 0:
            raise ValueError("Час очікування повинен бути додатним")

        difference = datetime.now(UTC) - self.last_activity

        return timedelta(0) <= difference <= timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class AuditRecord:
    """Запис журналу аудиту."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал подій безпеки."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def add_log(
        self,
        username: str,
        action: str,
    ) -> None:
        """Додавання події."""

        record = AuditRecord(
            timestamp=datetime.now(UTC),
            username=username,
            action=action,
        )

        self._records.append(record)

    def show_all(self) -> list[AuditRecord]:
        """Отримання всіх подій."""
        return list(self._records)


class UserAccount:
    """Обліковий запис користувача."""

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:

        self.user = user
        self.session = session

        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(
        self,
        username: str,
        password: str,
        ip: str,
    ) -> bool:
        """Авторизація користувача."""

        if (
            self.user.username != username
            or not self.user.active
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(
                username,
                "login_failure",
            )

            return False

        self.session = Session(ip)

        self.session.touch()

        self.audit_log.add_log(
            username,
            "login_success",
        )

        return True

    def is_authenticated(self) -> bool:
        """Перевірка авторизації."""

        return self.session is not None and self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        """Завершення сеансу."""

        if self.session is not None:
            self.session = None

            self.audit_log.add_log(
                self.user.username,
                "logout",
            )

    def __getitem__(self, key: str) -> Any:
        """Отримання дозволених атрибутів."""

        if key in (
            "user",
            "session",
            "audit_log",
        ):
            return getattr(self, key)

        raise KeyError(f"Доступ до ключа '{key}' заборонено")

    def __setitem__(
        self,
        key: str,
        value: Any,
    ) -> None:
        """Зміна дозволених атрибутів."""

        allowed_types = {
            "user": User,
            "session": (Session, type(None)),
            "audit_log": AuditLog,
        }

        if key not in allowed_types:
            raise KeyError(f"Зміна ключа '{key}' заборонена")

        if not isinstance(
            value,
            allowed_types[key],
        ):
            raise TypeError(f"Некоректний тип для '{key}'")

        setattr(self, key, value)
