"""
Лабораторна робота №2
Тема: Розробка консольних утиліт для задач кібербезпеки

Виконала: Данилович Анастасія
Група: КБ-201
Варіант: 5

Головний файл запуску програми.
"""

import argparse
from datetime import UTC, datetime, timedelta

from labs.lab02.task1 import Admin, AuditLog, User, UserAccount


def run_demo():
    """
    Демонстрація роботи першого завдання.
    """

    print("=" * 60)
    print("ЛАБОРАТОРНА РОБОТА №2")
    print("Виконала: Данилович Анастасія")
    print("Група: КБ-201")
    print("Варіант: 5")
    print("=" * 60)

    print("\nЗАВДАННЯ №1")
    print("МОДЕЛЬ КОРИСТУВАЧА ТА БЕЗПЕЧНИХ СЕСІЙ")
    print("=" * 60)

    # --------------------------------------------------
    # 1. СТВОРЕННЯ КОРИСТУВАЧА
    # --------------------------------------------------

    print("\n[1] Створення користувача")

    user = User(username="anastasia", email="anastasia@university.ua")

    user.set_password("AnastasiaSecurePassword2026!")

    print("Користувача успішно створено:")
    print(user)

    # --------------------------------------------------
    # 2. ПЕРЕВІРКА ЕЛЕКТРОННОЇ ПОШТИ
    # --------------------------------------------------

    print("\n[2] Перевірка електронної пошти")

    try:
        user.email = "wrong-email"

    except ValueError as error:
        print("Некоректна електронна адреса:")
        print(error)

    user.email = "anastasia.danylovych@university.ua"

    print("Правильна електронна адреса:")
    print(user.email)

    # --------------------------------------------------
    # 3. СТВОРЕННЯ АДМІНІСТРАТОРА
    # --------------------------------------------------

    print("\n[3] Створення адміністратора")

    admin = Admin(username="administrator", email="admin@university.ua")

    admin.grant_permission("READ_LOGS")
    admin.grant_permission("MANAGE_USERS")

    print("Адміністратора створено:")
    print(admin)

    print("Право READ_LOGS:", admin.has_permission("READ_LOGS"))

    print("Право DELETE_DATABASE:", admin.has_permission("DELETE_DATABASE"))

    admin.revoke_permission("MANAGE_USERS")

    print("Права після видалення MANAGE_USERS:")
    print(admin)

    # --------------------------------------------------
    # 4. ПЕРЕВІРКА АВТОРИЗАЦІЇ
    # --------------------------------------------------

    print("\n[4] Перевірка авторизації користувача")

    audit = AuditLog()

    account = UserAccount(user=user, audit_log=audit)

    # Перевірка неправильного пароля

    result = account.login(
        username="anastasia", password="WrongPassword", ip="127.0.0.1"
    )

    print("Вхід із неправильним паролем:", result)

    # Перевірка правильного пароля

    result = account.login(
        username="anastasia", password="AnastasiaSecurePassword2026!", ip="127.0.0.1"
    )

    print("Вхід із правильним паролем:", result)

    print("Користувач авторизований:", account.is_authenticated())

    # --------------------------------------------------
    # 5. ПЕРЕВІРКА ТАЙМАУТУ СЕСІЇ
    # --------------------------------------------------

    print("\n[5] Перевірка часу активності сесії")

    if account.session is not None:
        account.session.last_activity = datetime.now(UTC) - timedelta(seconds=1000)

    print("Сесія після 1000 секунд бездіяльності:", account.is_authenticated())

    # --------------------------------------------------
    # 6. ПОВТОРНИЙ ВХІД ТА ВИХІД
    # --------------------------------------------------

    print("\n[6] Повторний вхід користувача")

    account.login(
        username="anastasia", password="AnastasiaSecurePassword2026!", ip="127.0.0.1"
    )

    print("Сесія після повторного входу:", account.is_authenticated())

    print("\nВиконуємо вихід із системи...")

    account.logout()

    print("Сесія після виходу:", account.is_authenticated())

    # --------------------------------------------------
    # 7. ПЕРЕВІРКА СПЕЦІАЛЬНИХ МЕТОДІВ
    # --------------------------------------------------

    print("\n[7] Перевірка спеціальних методів")

    print("\nОтримання користувача через account['user']:")

    print(account["user"])

    print("\nПеревірка захисту атрибутів:")

    try:
        print(account["__password_hash"])

    except KeyError as error:
        print("Доступ заборонено:", error)

    print("\nПеревірка некоректного типу даних:")

    try:
        account["user"] = 123

    except TypeError as error:
        print("Помилка типу:", error)

    # --------------------------------------------------
    # 8. ЖУРНАЛ ПОДІЙ БЕЗПЕКИ
    # --------------------------------------------------

    print("\n[8] Журнал подій безпеки")

    print("-" * 60)

    for record in audit.show_all():
        print(
            f"Час: {record.timestamp} | "
            f"Користувач: {record.username} | "
            f"Подія: {record.action}"
        )

    print("-" * 60)

    print("\nЗАВДАННЯ №1 УСПІШНО ВИКОНАНО")
    print("=" * 60)


def main():
    """
    Головна функція лабораторної роботи.
    """

    parser = argparse.ArgumentParser(
        description=("Лабораторна робота №2. Данилович Анастасія. Варіант 5.")
    )

    subparsers = parser.add_subparsers(dest="command")

    # Команда запуску першого завдання

    subparsers.add_parser("demo", help="Запуск демонстрації першого завдання")

    # Команда запуску другого завдання

    scan_parser = subparsers.add_parser(
        "scan", help="Сканування доступності мережевих сервісів"
    )

    scan_parser.add_argument(
        "--targets", required=True, help="Шлях до JSON або CSV файлу з адресами"
    )

    scan_parser.add_argument(
        "--timeout", type=float, default=2.0, help="Час очікування відповіді в секундах"
    )

    scan_parser.add_argument(
        "--out-csv",
        default="labs/lab02/data/scan_results.csv",
        help="Шлях до файлу результатів",
    )

    scan_parser.add_argument(
        "--verbose", action="store_true", help="Увімкнення детального журналу"
    )

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()

    elif args.command == "scan":
        from labs.lab02.task2 import scan_services

        scan_services(
            targets_path=args.targets,
            timeout=args.timeout,
            output_path=args.out_csv,
            verbose=args.verbose,
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
