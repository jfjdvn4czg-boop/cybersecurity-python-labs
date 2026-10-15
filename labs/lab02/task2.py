"""Завдання №2. Варіант №5.

Консольна утиліта для перевірки доступності мережевих сервісів.
Підтримує вхідні файли JSON і CSV, TCP-перевірку, журналювання
та збереження результатів у CSV.
"""

import csv
import json
import logging
import socket
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def load_targets(targets_path):
    """Завантажує список мережевих сервісів із JSON або CSV."""

    path = Path(targets_path)

    if not path.exists():
        raise FileNotFoundError(f"Файл із мережевими сервісами не знайдено: {path}")

    extension = path.suffix.lower()

    if extension == ".json":
        with path.open("r", encoding="utf-8") as file:
            targets = json.load(file)

    elif extension == ".csv":
        with path.open("r", encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)
            targets = list(reader)

    else:
        raise ValueError("Непідтримуваний формат файлу. Використовуйте JSON або CSV.")

    if not isinstance(targets, list):
        raise TypeError("Файл повинен містити список мережевих сервісів")

    validated_targets = []

    for target in targets:
        if not isinstance(target, dict):
            raise TypeError("Кожна ціль повинна містити host і port")

        if "host" not in target or "port" not in target:
            raise ValueError("Кожна ціль повинна містити поля host і port")

        host = str(target["host"]).strip()

        if not host:
            raise ValueError("Адреса сервера не може бути порожньою")

        try:
            port = int(target["port"])
        except (TypeError, ValueError) as error:
            raise ValueError(f"Некоректний номер порту для {host}") from error

        if not 1 <= port <= 65535:
            raise ValueError(f"Порт {port} має бути в діапазоні від 1 до 65535")

        validated_targets.append(
            {
                "host": host,
                "port": port,
            }
        )

    return validated_targets


def check_service(host, port, timeout=2.0):
    """Перевіряє доступність TCP-сервісу."""

    start_time = time.perf_counter()

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ):
            status = "ONLINE"
            details = "З'єднання встановлено"

    except TimeoutError:
        status = "TIMEOUT"
        details = "Перевищено час очікування відповіді"

    except OSError as error:
        status = "OFFLINE"
        details = str(error)

    response_time_ms = round(
        (time.perf_counter() - start_time) * 1000,
        2,
    )

    return {
        "host": host,
        "port": port,
        "status": status,
        "response_time_ms": response_time_ms,
        "details": details,
    }


def save_results(results, output_path):
    """Зберігає результати сканування у CSV-файл."""

    path = Path(output_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "host",
        "port",
        "status",
        "response_time_ms",
        "details",
    ]

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(results)


def configure_logging(log_path, verbose=False):
    """Налаштовує журналювання подій сканера."""

    path = Path(log_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    logger.propagate = False

    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()

    file_handler = logging.FileHandler(
        path,
        encoding="utf-8",
    )

    file_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )

    logger.addHandler(file_handler)


def scan_services(
    targets_path,
    timeout=2.0,
    output_path="labs/lab02/data/scan_results.csv",
    verbose=False,
):
    """Запускає перевірку мережевих сервісів."""

    targets = load_targets(targets_path)

    output_path = Path(output_path)
    log_path = output_path.parent / "scanner.log"

    configure_logging(
        log_path=log_path,
        verbose=verbose,
    )

    print()
    print("=" * 60)
    print("ЛАБОРАТОРНА РОБОТА №2")
    print("ЗАВДАННЯ №2 — ВАРІАНТ 5")
    print("ПЕРЕВІРКА ДОСТУПНОСТІ МЕРЕЖЕВИХ СЕРВІСІВ")
    print("=" * 60)

    print("Виконала: Данилович Анастасія")
    print("Група: КБ-201")
    print(f"Кількість сервісів для перевірки: {len(targets)}")
    print(f"Час очікування: {timeout} с")
    print()

    results = []

    for target in targets:
        host = target["host"]
        port = target["port"]

        if verbose:
            print(f"Перевіряємо {host}:{port} ...")

        logger.info(
            "Початок перевірки %s:%s",
            host,
            port,
        )

        result = check_service(
            host=host,
            port=port,
            timeout=timeout,
        )

        results.append(result)

        print(f"{host}:{port} {result['status']} {result['response_time_ms']} мс")

        logger.info(
            "Результат %s:%s — %s, %.2f мс",
            host,
            port,
            result["status"],
            result["response_time_ms"],
        )

    save_results(
        results=results,
        output_path=output_path,
    )

    online_count = sum(result["status"] == "ONLINE" for result in results)

    offline_count = sum(result["status"] == "OFFLINE" for result in results)

    timeout_count = sum(result["status"] == "TIMEOUT" for result in results)

    print()
    print("-" * 60)
    print(f"ONLINE: {online_count}")
    print(f"OFFLINE: {offline_count}")
    print(f"TIMEOUT: {timeout_count}")
    print("-" * 60)

    print(f"Результати збережено у: {output_path}")
    print(f"Журнал подій збережено у: {log_path}")

    print()
    print("ЗАВДАННЯ №2 ВИКОНАНО")

    return results
