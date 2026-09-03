import platform
import re
import socket
import subprocess
import time
import csv

from pathlib import Path
from dataclasses import dataclass


class HostnameResult:
    def __init__(
        self,
        hostname: str | None,
        resolved: bool,
        duration_ms: int,
        message: str | None = None,
    ):
        self.hostname = hostname
        self.resolved = resolved
        self.duration_ms = duration_ms
        self.message = message


class MacAddressResult:
    def __init__(
        self,
        mac_address: str | None,
        resolved: bool,
        duration_ms: int,
        message: str | None = None,
    ):
        self.mac_address = mac_address
        self.resolved = resolved
        self.duration_ms = duration_ms
        self.message = message


@dataclass
class VendorResult:
    vendor: str | None
    resolved: bool
    prefix: str | None
    message: str | None


class NetworkInfoScanner:

    # ==========================================================
    # HOSTNAME
    # ==========================================================

    def resolve_hostname(
        self,
        ip_address: str,
    ) -> HostnameResult:

        started = time.perf_counter()

        try:
            hostname, aliases, addresses = socket.gethostbyaddr(
                ip_address
            )

            duration_ms = int(
                (time.perf_counter() - started) * 1000
            )

            hostname = hostname.strip()

            if not hostname:
                return HostnameResult(
                    hostname=None,
                    resolved=False,
                    duration_ms=duration_ms,
                    message="Hostname não identificado",
                )

            return HostnameResult(
                hostname=hostname,
                resolved=True,
                duration_ms=duration_ms,
                message="Hostname identificado",
            )

        except (
            socket.herror,
            socket.gaierror,
        ):
            duration_ms = int(
                (time.perf_counter() - started) * 1000
            )

            return HostnameResult(
                hostname=None,
                resolved=False,
                duration_ms=duration_ms,
                message="Hostname não encontrado via DNS reverso",
            )

        except Exception as error:
            duration_ms = int(
                (time.perf_counter() - started) * 1000
            )

            return HostnameResult(
                hostname=None,
                resolved=False,
                duration_ms=duration_ms,
                message=str(error),
            )

    # ==========================================================
    # MAC ADDRESS / ARP
    # ==========================================================

    def resolve_mac_address(
        self,
        ip_address: str,
    ) -> MacAddressResult:

        started = time.perf_counter()

        try:
            system = platform.system().lower()

            if system == "windows":
                output = self._get_windows_arp(ip_address)

            elif system == "linux":
                output = self._get_linux_neighbor(ip_address)

            else:
                duration_ms = int(
                    (time.perf_counter() - started) * 1000
                )

                return MacAddressResult(
                    mac_address=None,
                    resolved=False,
                    duration_ms=duration_ms,
                    message=(
                        f"Sistema operacional não suportado: "
                        f"{system}"
                    ),
                )

            mac_address = self._extract_mac_address(output)

            duration_ms = int(
                (time.perf_counter() - started) * 1000
            )

            if not mac_address:
                return MacAddressResult(
                    mac_address=None,
                    resolved=False,
                    duration_ms=duration_ms,
                    message="MAC não encontrado na tabela ARP",
                )

            return MacAddressResult(
                mac_address=mac_address,
                resolved=True,
                duration_ms=duration_ms,
                message="MAC identificado via ARP",
            )

        except Exception as error:
            duration_ms = int(
                (time.perf_counter() - started) * 1000
            )

            return MacAddressResult(
                mac_address=None,
                resolved=False,
                duration_ms=duration_ms,
                message=str(error),
            )

    # ==========================================================
    # FABRICANTE / OUI
    # ==========================================================

    def resolve_vendor(
        self,
        mac_address: str | None,
    ) -> VendorResult:

        if not mac_address:
            return VendorResult(
                vendor=None,
                resolved=False,
                prefix=None,
                message="MAC não informado",
            )

        normalized_mac = re.sub(
            r"[^0-9A-Fa-f]",
            "",
            mac_address,
        ).upper()

        if len(normalized_mac) != 12:
            return VendorResult(
                vendor=None,
                resolved=False,
                prefix=None,
                message="MAC inválido",
            )

        database_path = (
            Path(__file__).resolve().parent.parent
            / "data"
            / "oui.csv"
        )

        if not database_path.exists():
            return VendorResult(
                vendor=None,
                resolved=False,
                prefix=None,
                message="Base OUI não encontrada",
            )

        try:
            with database_path.open(
                "r",
                encoding="utf-8-sig",
                newline="",
            ) as csv_file:

                reader = csv.DictReader(csv_file)

                matches = []

                for row in reader:
                    row_prefix = (
                        row.get("prefix") or ""
                    ).strip().upper()

                    vendor = (
                        row.get("vendor") or ""
                    ).strip()

                    assignment_type = (
                        row.get("assignment_type") or ""
                    ).strip().upper()

                    if not row_prefix or not vendor:
                        continue

                    if normalized_mac.startswith(row_prefix):
                        matches.append(
                            {
                                "prefix": row_prefix,
                                "vendor": vendor,
                                "assignment_type": assignment_type,
                            }
                        )

                if matches:
                    # Prioriza o prefixo mais específico:
                    # MA-S -> MA-M -> MA-L
                    best_match = max(
                        matches,
                        key=lambda item: len(
                            item["prefix"]
                        ),
                    )

                    return VendorResult(
                        vendor=best_match["vendor"],
                        resolved=True,
                        prefix=best_match["prefix"],
                        message=(
                            "Fabricante identificado via "
                            f"{best_match['assignment_type']}"
                        ),
                    )

            return VendorResult(
                vendor=None,
                resolved=False,
                prefix=None,
                message="Fabricante não encontrado na base OUI",
            )

        except (OSError, csv.Error) as error:
            return VendorResult(
                vendor=None,
                resolved=False,
                prefix=None,
                message=(
                    f"Erro ao consultar base OUI: {error}"
                ),
            )
    # ==========================================================
    # WINDOWS ARP
    # ==========================================================

    def _get_windows_arp(
        self,
        ip_address: str,
    ) -> str:

        result = subprocess.run(
            [
                "arp",
                "-a",
                ip_address,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
            errors="ignore",
        )

        return result.stdout

    # ==========================================================
    # LINUX NEIGHBOR
    # ==========================================================

    def _get_linux_neighbor(
        self,
        ip_address: str,
    ) -> str:

        result = subprocess.run(
            [
                "ip",
                "neigh",
                "show",
                ip_address,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
            errors="ignore",
        )

        return result.stdout

    # ==========================================================
    # NORMALIZAÇÃO DO MAC
    # ==========================================================

    def _extract_mac_address(
        self,
        text: str,
    ) -> str | None:

        if not text:
            return None

        pattern = (
            r"\b"
            r"([0-9A-Fa-f]{2})"
            r"[:-]"
            r"([0-9A-Fa-f]{2})"
            r"[:-]"
            r"([0-9A-Fa-f]{2})"
            r"[:-]"
            r"([0-9A-Fa-f]{2})"
            r"[:-]"
            r"([0-9A-Fa-f]{2})"
            r"[:-]"
            r"([0-9A-Fa-f]{2})"
            r"\b"
        )

        match = re.search(
            pattern,
            text,
        )

        if not match:
            return None

        return ":".join(
            part.upper()
            for part in match.groups()
        )