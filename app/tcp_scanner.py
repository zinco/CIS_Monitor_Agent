import socket
import time


class TcpResult:
    def __init__(
        self,
        online: bool,
        port: int | None,
        duration_ms: int,
        message: str | None = None,
    ):
        self.online = online
        self.port = port
        self.duration_ms = duration_ms
        self.message = message


class TcpPortResult:
    def __init__(
        self,
        port: int,
        open: bool,
        duration_ms: int,
        message: str | None = None,
    ):
        self.port = port
        self.open = open
        self.duration_ms = duration_ms
        self.message = message


class TcpScanner:

    # ==========================================================
    # VERIFICAÇÃO RÁPIDA
    # ==========================================================
    #
    # Mantido para o monitoramento normal.
    # Para na primeira porta que responder.
    #
    # ==========================================================

    def check(
        self,
        ip_address: str,
        ports: list[int],
        timeout_seconds: int = 3,
    ) -> TcpResult:

        valid_ports = self._normalize_ports(
            ports
        )

        if not valid_ports:
            return TcpResult(
                online=False,
                port=None,
                duration_ms=0,
                message=(
                    "Nenhuma porta cadastrada "
                    "para teste"
                ),
            )

        started = time.perf_counter()

        for port in valid_ports:

            try:

                with socket.create_connection(
                    (ip_address, port),
                    timeout=timeout_seconds,
                ):

                    duration_ms = int(
                        (
                            time.perf_counter()
                            - started
                        )
                        * 1000
                    )

                    return TcpResult(
                        online=True,
                        port=port,
                        duration_ms=duration_ms,
                    )

            except (
                socket.timeout,
                ConnectionRefusedError,
                OSError,
            ):
                continue

        duration_ms = int(
            (
                time.perf_counter()
                - started
            )
            * 1000
        )

        return TcpResult(
            online=False,
            port=None,
            duration_ms=duration_ms,
            message="Nenhuma porta respondeu",
        )


    # ==========================================================
    # SCAN DE TODAS AS PORTAS
    # ==========================================================
    #
    # Usado pelo Scanner manual.
    # Testa todas as portas recebidas.
    #
    # ==========================================================

    def scan_ports(
        self,
        ip_address: str,
        ports: list[int],
        timeout_seconds: int = 3,
    ) -> list[TcpPortResult]:

        valid_ports = self._normalize_ports(
            ports
        )

        results = []

        for port in valid_ports:

            started = time.perf_counter()

            try:

                with socket.create_connection(
                    (ip_address, port),
                    timeout=timeout_seconds,
                ):

                    duration_ms = int(
                        (
                            time.perf_counter()
                            - started
                        )
                        * 1000
                    )

                    results.append(
                        TcpPortResult(
                            port=port,
                            open=True,
                            duration_ms=duration_ms,
                        )
                    )

            except socket.timeout:

                duration_ms = int(
                    (
                        time.perf_counter()
                        - started
                    )
                    * 1000
                )

                results.append(
                    TcpPortResult(
                        port=port,
                        open=False,
                        duration_ms=duration_ms,
                        message="Timeout",
                    )
                )

            except ConnectionRefusedError:

                duration_ms = int(
                    (
                        time.perf_counter()
                        - started
                    )
                    * 1000
                )

                results.append(
                    TcpPortResult(
                        port=port,
                        open=False,
                        duration_ms=duration_ms,
                        message="Conexão recusada",
                    )
                )

            except OSError as error:

                duration_ms = int(
                    (
                        time.perf_counter()
                        - started
                    )
                    * 1000
                )

                results.append(
                    TcpPortResult(
                        port=port,
                        open=False,
                        duration_ms=duration_ms,
                        message=str(error),
                    )
                )

        return results


    # ==========================================================
    # NORMALIZAÇÃO DAS PORTAS
    # ==========================================================

    def _normalize_ports(
        self,
        ports: list[int],
    ) -> list[int]:

        valid_ports = []

        for port in ports:

            if not port:
                continue

            try:
                port = int(port)
            except (
                TypeError,
                ValueError,
            ):
                continue

            if port < 1 or port > 65535:
                continue

            if port not in valid_ports:
                valid_ports.append(port)

        return valid_ports