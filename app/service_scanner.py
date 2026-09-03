import re
import socket
import ssl
import time
import urllib.error
import urllib.request


# ==========================================================
# RESULTADO HTTP / HTTPS
# ==========================================================


class HttpServiceResult:
    def __init__(
        self,
        detected: bool,
        scheme: str,
        port: int,
        status_code: int | None,
        server: str | None,
        title: str | None,
        duration_ms: int,
        message: str | None = None,
    ):
        self.detected = detected
        self.scheme = scheme
        self.port = port
        self.status_code = status_code
        self.server = server
        self.title = title
        self.duration_ms = duration_ms
        self.message = message

    def __repr__(self):
        return (
            "HttpServiceResult("
            f"detected={self.detected}, "
            f"scheme={self.scheme!r}, "
            f"port={self.port}, "
            f"status_code={self.status_code}, "
            f"server={self.server!r}, "
            f"title={self.title!r}, "
            f"duration_ms={self.duration_ms}, "
            f"message={self.message!r}"
            ")"
        )


# ==========================================================
# RESULTADO RTSP
# ==========================================================


class RtspServiceResult:
    def __init__(
        self,
        detected: bool,
        port: int,
        status_code: int | None,
        status_text: str | None,
        server: str | None,
        public_methods: str | None,
        duration_ms: int,
        message: str | None = None,
    ):
        self.detected = detected
        self.port = port
        self.status_code = status_code
        self.status_text = status_text
        self.server = server
        self.public_methods = public_methods
        self.duration_ms = duration_ms
        self.message = message

    def __repr__(self):
        return (
            "RtspServiceResult("
            f"detected={self.detected}, "
            f"port={self.port}, "
            f"status_code={self.status_code}, "
            f"status_text={self.status_text!r}, "
            f"server={self.server!r}, "
            f"public_methods={self.public_methods!r}, "
            f"duration_ms={self.duration_ms}, "
            f"message={self.message!r}"
            ")"
        )


# ==========================================================
# SERVICE SCANNER
# ==========================================================


class ServiceScanner:

    # ======================================================
    # HTTP / HTTPS
    # ======================================================

    def scan_http(
        self,
        ip_address: str,
        port: int,
        timeout_seconds: int = 4,
    ) -> HttpServiceResult:

        started = time.perf_counter()

        scheme = (
            "https"
            if port == 443
            else "http"
        )

        url = (
            f"{scheme}://"
            f"{ip_address}:{port}/"
        )

        try:

            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": (
                        "CIS-Monitor-Agent/1.0"
                    ),
                    "Accept": (
                        "text/html,"
                        "application/xhtml+xml,"
                        "application/json;q=0.9,"
                        "*/*;q=0.8"
                    ),
                },
                method="GET",
            )

            context = None

            if scheme == "https":

                context = (
                    ssl.create_default_context()
                )

                # DVRs e câmeras frequentemente
                # utilizam certificados autoassinados.
                context.check_hostname = False

                context.verify_mode = (
                    ssl.CERT_NONE
                )

            with urllib.request.urlopen(
                request,
                timeout=timeout_seconds,
                context=context,
            ) as response:

                status_code = response.status

                server = (
                    response.headers.get(
                        "Server"
                    )
                )

                content_type = (
                    response.headers.get(
                        "Content-Type",
                        "",
                    )
                )

                body = response.read(
                    65536
                )

                title = None

                if (
                    "text/html"
                    in content_type.lower()
                    or not content_type
                ):

                    title = (
                        self._extract_title(
                            body
                        )
                    )

                duration_ms = int(
                    (
                        time.perf_counter()
                        - started
                    )
                    * 1000
                )

                return HttpServiceResult(
                    detected=True,
                    scheme=scheme,
                    port=port,
                    status_code=status_code,
                    server=server,
                    title=title,
                    duration_ms=duration_ms,
                    message=(
                        "Serviço HTTP "
                        "identificado"
                    ),
                )

        except urllib.error.HTTPError as error:

            duration_ms = int(
                (
                    time.perf_counter()
                    - started
                )
                * 1000
            )

            server = None

            if error.headers:

                server = (
                    error.headers.get(
                        "Server"
                    )
                )

            body = b""

            try:

                body = error.read(
                    65536
                )

            except Exception:
                pass

            title = (
                self._extract_title(
                    body
                )
            )

            # 401, 403, 404 etc. continuam
            # confirmando a existência do HTTP.
            return HttpServiceResult(
                detected=True,
                scheme=scheme,
                port=port,
                status_code=error.code,
                server=server,
                title=title,
                duration_ms=duration_ms,
                message=(
                    f"Serviço HTTP respondeu "
                    f"com status {error.code}"
                ),
            )

        except urllib.error.URLError as error:

            duration_ms = int(
                (
                    time.perf_counter()
                    - started
                )
                * 1000
            )

            return HttpServiceResult(
                detected=False,
                scheme=scheme,
                port=port,
                status_code=None,
                server=None,
                title=None,
                duration_ms=duration_ms,
                message=str(
                    error.reason
                ),
            )

        except (
            TimeoutError,
            socket.timeout,
        ):

            duration_ms = int(
                (
                    time.perf_counter()
                    - started
                )
                * 1000
            )

            return HttpServiceResult(
                detected=False,
                scheme=scheme,
                port=port,
                status_code=None,
                server=None,
                title=None,
                duration_ms=duration_ms,
                message="Timeout HTTP",
            )

        except Exception as error:

            duration_ms = int(
                (
                    time.perf_counter()
                    - started
                )
                * 1000
            )

            return HttpServiceResult(
                detected=False,
                scheme=scheme,
                port=port,
                status_code=None,
                server=None,
                title=None,
                duration_ms=duration_ms,
                message=str(error),
            )

    # ======================================================
    # RTSP
    # ======================================================

    def scan_rtsp(
        self,
        ip_address: str,
        port: int = 554,
        timeout_seconds: int = 4,
    ) -> RtspServiceResult:

        started = time.perf_counter()

        request = (
            f"OPTIONS "
            f"rtsp://{ip_address}:{port}/ "
            f"RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: "
            f"CIS-Monitor-Agent/1.0\r\n"
            f"\r\n"
        )

        try:

            with socket.create_connection(
                (
                    ip_address,
                    port,
                ),
                timeout=timeout_seconds,
            ) as sock:

                sock.settimeout(
                    timeout_seconds
                )

                sock.sendall(
                    request.encode(
                        "ascii"
                    )
                )

                response = sock.recv(
                    8192
                )

            duration_ms = int(
                (
                    time.perf_counter()
                    - started
                )
                * 1000
            )

            if not response:

                return RtspServiceResult(
                    detected=False,
                    port=port,
                    status_code=None,
                    status_text=None,
                    server=None,
                    public_methods=None,
                    duration_ms=duration_ms,
                    message=(
                        "Porta respondeu, "
                        "mas não retornou "
                        "resposta RTSP"
                    ),
                )

            text = response.decode(
                "utf-8",
                errors="ignore",
            )

            lines = text.splitlines()

            if not lines:

                return RtspServiceResult(
                    detected=False,
                    port=port,
                    status_code=None,
                    status_text=None,
                    server=None,
                    public_methods=None,
                    duration_ms=duration_ms,
                    message=(
                        "Resposta RTSP inválida"
                    ),
                )

            status_line = (
                lines[0].strip()
            )

            match = re.match(
                (
                    r"RTSP/\d+\.\d+"
                    r"\s+(\d+)\s*(.*)"
                ),
                status_line,
                flags=re.IGNORECASE,
            )

            if not match:

                return RtspServiceResult(
                    detected=False,
                    port=port,
                    status_code=None,
                    status_text=None,
                    server=None,
                    public_methods=None,
                    duration_ms=duration_ms,
                    message=(
                        "Serviço na porta "
                        "não respondeu como RTSP"
                    ),
                )

            status_code = int(
                match.group(1)
            )

            status_text = (
                match.group(2).strip()
                or None
            )

            server = None
            public_methods = None

            for line in lines[1:]:

                if ":" not in line:
                    continue

                name, value = (
                    line.split(
                        ":",
                        1,
                    )
                )

                name = (
                    name.strip().lower()
                )

                value = value.strip()

                if name == "server":

                    server = value

                elif name == "public":

                    public_methods = value

            return RtspServiceResult(
                detected=True,
                port=port,
                status_code=status_code,
                status_text=status_text,
                server=server,
                public_methods=public_methods,
                duration_ms=duration_ms,
                message=(
                    "Serviço RTSP "
                    "identificado"
                ),
            )

        except (
            TimeoutError,
            socket.timeout,
        ):

            duration_ms = int(
                (
                    time.perf_counter()
                    - started
                )
                * 1000
            )

            return RtspServiceResult(
                detected=False,
                port=port,
                status_code=None,
                status_text=None,
                server=None,
                public_methods=None,
                duration_ms=duration_ms,
                message="Timeout RTSP",
            )

        except ConnectionRefusedError:

            duration_ms = int(
                (
                    time.perf_counter()
                    - started
                )
                * 1000
            )

            return RtspServiceResult(
                detected=False,
                port=port,
                status_code=None,
                status_text=None,
                server=None,
                public_methods=None,
                duration_ms=duration_ms,
                message=(
                    "Conexão RTSP recusada"
                ),
            )

        except Exception as error:

            duration_ms = int(
                (
                    time.perf_counter()
                    - started
                )
                * 1000
            )

            return RtspServiceResult(
                detected=False,
                port=port,
                status_code=None,
                status_text=None,
                server=None,
                public_methods=None,
                duration_ms=duration_ms,
                message=str(error),
            )

    # ======================================================
    # EXTRAÇÃO DO TITLE HTML
    # ======================================================

    def _extract_title(
        self,
        body: bytes,
    ) -> str | None:

        if not body:
            return None

        try:

            text = body.decode(
                "utf-8",
                errors="ignore",
            )

            match = re.search(
                (
                    r"<title[^>]*>"
                    r"(.*?)"
                    r"</title>"
                ),
                text,
                flags=(
                    re.IGNORECASE
                    | re.DOTALL
                ),
            )

            if not match:
                return None

            title = re.sub(
                r"\s+",
                " ",
                match.group(1),
            ).strip()

            if not title:
                return None

            return title[:200]

        except Exception:
            return None