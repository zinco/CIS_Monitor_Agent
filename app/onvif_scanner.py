import base64
import hashlib
import os
import re
import socket
import time

from dataclasses import dataclass
from datetime import datetime, timezone
from urllib import request
from urllib.error import HTTPError, URLError


# ==========================================================
# RESULTADOS
# ==========================================================


@dataclass
class OnvifDetectionResult:
    detected: bool
    port: int | None
    status_code: int | None
    endpoint: str | None
    duration_ms: int
    message: str | None = None


@dataclass
class OnvifDeviceInfoResult:
    resolved: bool
    manufacturer: str | None
    model: str | None
    firmware_version: str | None
    serial_number: str | None
    hardware_id: str | None
    status_code: int | None
    duration_ms: int
    message: str | None = None


# ==========================================================
# SCANNER ONVIF
# ==========================================================


class OnvifScanner:

    DEFAULT_PORTS = [
        80,
        8000,
        8080,
        8899,
    ]

    # ======================================================
    # DETECÇÃO ONVIF
    # ======================================================

    def detect(
        self,
        ip_address: str,
        ports: list[int] | None = None,
        timeout_seconds: float = 3.0,
    ) -> OnvifDetectionResult:

        started = time.perf_counter()

        ports_to_test = (
            ports
            or self.DEFAULT_PORTS
        )

        for port in ports_to_test:

            if not self._is_tcp_open(
                ip_address,
                port,
                timeout_seconds,
            ):
                continue

            result = self._probe_onvif(
                ip_address,
                port,
                timeout_seconds,
            )

            if result.detected:
                return result

        duration_ms = int(
            (
                time.perf_counter()
                - started
            )
            * 1000
        )

        return OnvifDetectionResult(
            detected=False,
            port=None,
            status_code=None,
            endpoint=None,
            duration_ms=duration_ms,
            message=(
                "Serviço ONVIF não identificado"
            ),
        )

    # ======================================================
    # GET DEVICE INFORMATION
    # ======================================================

    def get_device_information(
        self,
        ip_address: str,
        username: str,
        password: str,
        port: int = 80,
        timeout_seconds: float = 3.0,
    ) -> OnvifDeviceInfoResult:

        started = time.perf_counter()

        endpoint = (
            f"http://{ip_address}:{port}"
            "/onvif/device_service"
        )

        security_header = (
            self._build_ws_security_header(
                username=username,
                password=password,
            )
        )

        xml_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <s:Header>
        {security_header}
    </s:Header>
    <s:Body>
        <tds:GetDeviceInformation/>
    </s:Body>
</s:Envelope>
"""

        req = request.Request(
            endpoint,
            data=xml_body.encode(
                "utf-8"
            ),
            method="POST",
            headers={
                "Content-Type":
                    "application/soap+xml; charset=utf-8",
                "User-Agent":
                    "CIS-Monitor-Agent/1.0",
            },
        )

        try:

            with request.urlopen(
                req,
                timeout=timeout_seconds,
            ) as response:

                status_code = (
                    response.status
                )

                body = response.read(
                    65536
                ).decode(
                    "utf-8",
                    errors="ignore",
                )

                duration_ms = int(
                    (
                        time.perf_counter()
                        - started
                    )
                    * 1000
                )

                manufacturer = (
                    self._extract_xml_value(
                        body,
                        "Manufacturer",
                    )
                )

                model = (
                    self._extract_xml_value(
                        body,
                        "Model",
                    )
                )

                firmware_version = (
                    self._extract_xml_value(
                        body,
                        "FirmwareVersion",
                    )
                )

                serial_number = (
                    self._extract_xml_value(
                        body,
                        "SerialNumber",
                    )
                )

                hardware_id = (
                    self._extract_xml_value(
                        body,
                        "HardwareId",
                    )
                )

                resolved = any(
                    [
                        manufacturer,
                        model,
                        firmware_version,
                        serial_number,
                        hardware_id,
                    ]
                )

                return OnvifDeviceInfoResult(
                    resolved=resolved,
                    manufacturer=manufacturer,
                    model=model,
                    firmware_version=(
                        firmware_version
                    ),
                    serial_number=(
                        serial_number
                    ),
                    hardware_id=(
                        hardware_id
                    ),
                    status_code=(
                        status_code
                    ),
                    duration_ms=(
                        duration_ms
                    ),
                    message=(
                        "Informações ONVIF identificadas"
                        if resolved
                        else
                        (
                            "ONVIF respondeu sem "
                            "informações de dispositivo"
                        )
                    ),
                )

        except HTTPError as exc:

            duration_ms = int(
                (
                    time.perf_counter()
                    - started
                )
                * 1000
            )

            body = ""

            try:
                body = (
                    exc.read()
                    .decode(
                        "utf-8",
                        errors="ignore",
                    )
                )
            except Exception:
                pass

            message = (
                self._extract_soap_fault(
                    body
                )
            )

            if not message:

                if exc.code in (
                    401,
                    403,
                ):
                    message = (
                        "Falha de autenticação ONVIF"
                    )
                else:
                    message = (
                        f"Erro HTTP ONVIF: "
                        f"{exc.code}"
                    )

            return OnvifDeviceInfoResult(
                resolved=False,
                manufacturer=None,
                model=None,
                firmware_version=None,
                serial_number=None,
                hardware_id=None,
                status_code=exc.code,
                duration_ms=duration_ms,
                message=message,
            )

        except (
            URLError,
            TimeoutError,
            ConnectionError,
            OSError,
        ) as exc:

            duration_ms = int(
                (
                    time.perf_counter()
                    - started
                )
                * 1000
            )

            return OnvifDeviceInfoResult(
                resolved=False,
                manufacturer=None,
                model=None,
                firmware_version=None,
                serial_number=None,
                hardware_id=None,
                status_code=None,
                duration_ms=duration_ms,
                message=str(exc),
            )

    # ======================================================
    # WS-SECURITY
    # ======================================================

    def _build_ws_security_header(
        self,
        username: str,
        password: str,
    ) -> str:

        nonce_bytes = os.urandom(
            16
        )

        nonce_base64 = (
            base64.b64encode(
                nonce_bytes
            )
            .decode(
                "ascii"
            )
        )

        created = (
            datetime.now(
                timezone.utc
            )
            .strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )
        )

        digest_source = (
            nonce_bytes
            + created.encode(
                "utf-8"
            )
            + password.encode(
                "utf-8"
            )
        )

        password_digest = (
            base64.b64encode(
                hashlib.sha1(
                    digest_source
                ).digest()
            )
            .decode(
                "ascii"
            )
        )

        username_xml = (
            self._xml_escape(
                username
            )
        )

        return f"""
<wsse:Security
    s:mustUnderstand="1"
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <wsse:UsernameToken>
        <wsse:Username>{username_xml}</wsse:Username>

        <wsse:Password
            Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password_digest}</wsse:Password>

        <wsse:Nonce
            EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_base64}</wsse:Nonce>

        <wsu:Created>{created}</wsu:Created>
    </wsse:UsernameToken>
</wsse:Security>
"""

    # ======================================================
    # PROBE ONVIF
    # ======================================================

    def _probe_onvif(
        self,
        ip_address: str,
        port: int,
        timeout_seconds: float,
    ) -> OnvifDetectionResult:

        started = time.perf_counter()

        endpoint = (
            f"http://{ip_address}:{port}"
            "/onvif/device_service"
        )

        xml_body = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Body>
        <GetSystemDateAndTime
            xmlns="http://www.onvif.org/ver10/device/wsdl"/>
    </s:Body>
</s:Envelope>
"""

        req = request.Request(
            endpoint,
            data=xml_body.encode(
                "utf-8"
            ),
            method="POST",
            headers={
                "Content-Type":
                    "application/soap+xml; charset=utf-8",
                "User-Agent":
                    "CIS-Monitor-Agent/1.0",
            },
        )

        try:

            with request.urlopen(
                req,
                timeout=timeout_seconds,
            ) as response:

                status_code = (
                    response.status
                )

                body = response.read(
                    32768
                ).decode(
                    "utf-8",
                    errors="ignore",
                )

                duration_ms = int(
                    (
                        time.perf_counter()
                        - started
                    )
                    * 1000
                )

                if self._looks_like_onvif(
                    body
                ):

                    return (
                        OnvifDetectionResult(
                            detected=True,
                            port=port,
                            status_code=(
                                status_code
                            ),
                            endpoint=endpoint,
                            duration_ms=(
                                duration_ms
                            ),
                            message=(
                                "Serviço ONVIF "
                                "identificado"
                            ),
                        )
                    )

        except HTTPError as exc:

            duration_ms = int(
                (
                    time.perf_counter()
                    - started
                )
                * 1000
            )

            body = ""

            try:
                body = (
                    exc.read()
                    .decode(
                        "utf-8",
                        errors="ignore",
                    )
                )
            except Exception:
                pass

            if (
                exc.code
                in (
                    400,
                    401,
                    403,
                    405,
                    500,
                )
                or self._looks_like_onvif(
                    body
                )
            ):

                return (
                    OnvifDetectionResult(
                        detected=True,
                        port=port,
                        status_code=exc.code,
                        endpoint=endpoint,
                        duration_ms=(
                            duration_ms
                        ),
                        message=(
                            "Endpoint ONVIF "
                            "respondeu e pode "
                            "exigir autenticação"
                        ),
                    )
                )

        except (
            URLError,
            TimeoutError,
            ConnectionError,
            OSError,
        ):
            pass

        duration_ms = int(
            (
                time.perf_counter()
                - started
            )
            * 1000
        )

        return OnvifDetectionResult(
            detected=False,
            port=port,
            status_code=None,
            endpoint=endpoint,
            duration_ms=duration_ms,
            message=(
                "ONVIF não confirmado "
                "nesta porta"
            ),
        )

    # ======================================================
    # TCP
    # ======================================================

    def _is_tcp_open(
        self,
        ip_address: str,
        port: int,
        timeout_seconds: float,
    ) -> bool:

        try:

            with socket.create_connection(
                (
                    ip_address,
                    port,
                ),
                timeout=timeout_seconds,
            ):
                return True

        except OSError:
            return False

    # ======================================================
    # IDENTIFICA RESPOSTA ONVIF
    # ======================================================

    def _looks_like_onvif(
        self,
        content: str,
    ) -> bool:

        if not content:
            return False

        content_lower = (
            content.lower()
        )

        markers = [
            "onvif.org",
            "device_service",
            "getsystemdateandtime",
            "getdeviceinformation",
            "soap-env",
            "soap:envelope",
            "s:envelope",
        ]

        return any(
            marker
            in content_lower
            for marker
            in markers
        )

    # ======================================================
    # EXTRAI VALOR DO XML
    # ======================================================

    def _extract_xml_value(
        self,
        xml_content: str,
        tag_name: str,
    ) -> str | None:

        pattern = (
            rf"<(?:\w+:)?{tag_name}"
            rf"(?:\s[^>]*)?>"
            rf"(.*?)"
            rf"</(?:\w+:)?{tag_name}>"
        )

        match = re.search(
            pattern,
            xml_content,
            re.IGNORECASE
            | re.DOTALL,
        )

        if not match:
            return None

        value = (
            match.group(1)
            .strip()
        )

        return (
            value
            or None
        )

    # ======================================================
    # SOAP FAULT
    # ======================================================

    def _extract_soap_fault(
        self,
        xml_content: str,
    ) -> str | None:

        if not xml_content:
            return None

        candidates = [
            "Text",
            "Reason",
            "faultstring",
        ]

        for tag_name in candidates:

            value = (
                self._extract_xml_value(
                    xml_content,
                    tag_name,
                )
            )

            if value:
                return value

        return None

    # ======================================================
    # ESCAPE XML
    # ======================================================

    def _xml_escape(
        self,
        value: str,
    ) -> str:

        return (
            value
            .replace(
                "&",
                "&amp;",
            )
            .replace(
                "<",
                "&lt;",
            )
            .replace(
                ">",
                "&gt;",
            )
            .replace(
                '"',
                "&quot;",
            )
            .replace(
                "'",
                "&apos;",
            )
        )