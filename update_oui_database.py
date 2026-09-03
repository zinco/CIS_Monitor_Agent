import csv
import io
import urllib.request
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_FILE = DATA_DIR / "oui.csv"


SOURCES = [
    {
        "type": "MA-L",
        "url": "https://standards-oui.ieee.org/oui/oui.csv",
    },
    {
        "type": "MA-M",
        "url": "https://standards-oui.ieee.org/oui28/mam.csv",
    },
    {
        "type": "MA-S",
        "url": "https://standards-oui.ieee.org/oui36/oui36.csv",
    },
]


def download_csv(url: str) -> str:
    print(f"Baixando: {url}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "CIS-Monitor-Agent/1.0",
        },
    )

    with urllib.request.urlopen(
        request,
        timeout=30,
    ) as response:
        return response.read().decode(
            "utf-8-sig",
            errors="replace",
        )


def normalize_assignment(
    assignment: str,
) -> str:
    return "".join(
        char
        for char in assignment.upper()
        if char in "0123456789ABCDEF"
    )


def main():
    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    records = []

    for source in SOURCES:
        source_type = source["type"]
        content = download_csv(
            source["url"]
        )

        reader = csv.DictReader(
            io.StringIO(content)
        )

        count = 0

        for row in reader:
            assignment = normalize_assignment(
                row.get("Assignment", "")
            )

            vendor = (
                row.get("Organization Name", "")
                or row.get("Organization", "")
            ).strip()

            if not assignment:
                continue

            if not vendor:
                continue

            records.append(
                {
                    "prefix": assignment,
                    "vendor": vendor,
                    "assignment_type": source_type,
                }
            )

            count += 1

        print(
            f"{source_type}: {count} registros"
        )

    # Mais específico primeiro:
    # MA-S (36 bits), MA-M (28 bits), MA-L (24 bits)
    records.sort(
        key=lambda item: len(
            item["prefix"]
        ),
        reverse=True,
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as output:
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "prefix",
                "vendor",
                "assignment_type",
            ],
        )

        writer.writeheader()
        writer.writerows(records)

    print()
    print("Base OUI atualizada com sucesso.")
    print(
        f"Total: {len(records)} registros"
    )
    print(
        f"Arquivo: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()