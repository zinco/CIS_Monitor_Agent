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


class TcpScanner:
    def check(
        self,
        ip_address: str,
        ports: list[int],
        timeout_seconds: int = 3,
    ) -> TcpResult:

        valid_ports = [
            int(port)
            for port in ports
            if port
        ]

        if not valid_ports:
            return TcpResult(
                online=False,
                port=None,
                duration_ms=0,
                message="Nenhuma porta cadastrada para teste",
            )

        started = time.perf_counter()

        for port in valid_ports:

            try:

                with socket.create_connection(
                    (ip_address, port),
                    timeout=timeout_seconds,
                ):

                    duration_ms = int(
                        (time.perf_counter() - started)
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
            (time.perf_counter() - started)
            * 1000
        )

        return TcpResult(
            online=False,
            port=None,
            duration_ms=duration_ms,
            message="Nenhuma porta respondeu",
        )