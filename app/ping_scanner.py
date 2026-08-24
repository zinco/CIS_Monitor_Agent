import platform
import re
import subprocess
import time


class PingResult:
    def __init__(
        self,
        online: bool,
        latency_ms: int | None,
        duration_ms: int,
        message: str | None = None,
    ):
        self.online = online
        self.latency_ms = latency_ms
        self.duration_ms = duration_ms
        self.message = message


class PingScanner:
    def ping(
        self,
        ip_address: str,
        timeout_seconds: int = 5,
    ) -> PingResult:

        system = platform.system().lower()

        if system == "windows":
            command = [
                "ping",
                "-n",
                "1",
                "-w",
                str(timeout_seconds * 1000),
                ip_address,
            ]
        else:
            command = [
                "ping",
                "-c",
                "1",
                "-W",
                str(timeout_seconds),
                ip_address,
            ]

        started = time.perf_counter()

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 2,
                errors="replace",
            )

            duration_ms = int(
                (time.perf_counter() - started) * 1000
            )

            output = (
                (result.stdout or "")
                + "\n"
                + (result.stderr or "")
            )

            # ------------------------------------------
            # Erros conhecidos de conectividade
            # ------------------------------------------

            if self._contains_failure_message(output):
                return PingResult(
                    online=False,
                    latency_ms=None,
                    duration_ms=duration_ms,
                    message="Destino inacessível",
                )

            # ------------------------------------------
            # Return code diferente de zero
            # ------------------------------------------

            if result.returncode != 0:
                return PingResult(
                    online=False,
                    latency_ms=None,
                    duration_ms=duration_ms,
                    message="Dispositivo não respondeu ao ping",
                )

            # ------------------------------------------
            # Extrai latência
            # ------------------------------------------

            latency = self._extract_latency(output)

            # ------------------------------------------
            # Windows:
            # returncode 0 sozinho não é confiável.
            # Precisamos confirmar resposta real.
            # ------------------------------------------

            if system == "windows":

                if not self._has_valid_windows_reply(
                    output,
                    ip_address,
                ):
                    return PingResult(
                        online=False,
                        latency_ms=None,
                        duration_ms=duration_ms,
                        message="Não houve resposta válida do dispositivo",
                    )

            # ------------------------------------------
            # Linux:
            # returncode 0 normalmente já representa
            # Echo Reply válido.
            # ------------------------------------------

            return PingResult(
                online=True,
                latency_ms=latency,
                duration_ms=duration_ms,
            )

        except subprocess.TimeoutExpired:

            duration_ms = int(
                (time.perf_counter() - started) * 1000
            )

            return PingResult(
                online=False,
                latency_ms=None,
                duration_ms=duration_ms,
                message="Timeout durante o ping",
            )

        except Exception as error:

            duration_ms = int(
                (time.perf_counter() - started) * 1000
            )

            return PingResult(
                online=False,
                latency_ms=None,
                duration_ms=duration_ms,
                message=str(error),
            )


    def _contains_failure_message(
        self,
        output: str,
    ) -> bool:

        failure_messages = [
            # Português - Windows
            "host de destino inacessível",
            "destino inacessível",
            "esgotado o tempo limite do pedido",
            "falha geral",
            "não foi possível encontrar o host",

            # Inglês - Windows/Linux
            "destination host unreachable",
            "destination net unreachable",
            "request timed out",
            "general failure",
            "unknown host",
            "name or service not known",
            "temporary failure in name resolution",
            "network is unreachable",
        ]

        output_lower = output.lower()

        return any(
            message in output_lower
            for message in failure_messages
        )


    def _has_valid_windows_reply(
        self,
        output: str,
        ip_address: str,
    ) -> bool:

        """
        Confirma que a resposta veio realmente
        do IP que estamos monitorando.

        Exemplo válido:
        Resposta de 192.168.62.246: bytes=32 tempo=1ms TTL=128

        Exemplo inválido:
        Resposta de 192.168.215.1: Host de destino inacessível.
        """

        escaped_ip = re.escape(ip_address)

        patterns = [
            rf"resposta de {escaped_ip}:.*(?:tempo|time)[=<]",
            rf"reply from {escaped_ip}:.*(?:time)[=<]",
            rf"reply from {escaped_ip}:.*ttl=",
            rf"resposta de {escaped_ip}:.*ttl=",
        ]

        for pattern in patterns:
            if re.search(
                pattern,
                output,
                re.IGNORECASE,
            ):
                return True

        return False


    def _extract_latency(
        self,
        output: str,
    ) -> int | None:

        patterns = [
            r"tempo[=<]\s*(\d+)\s*ms",
            r"time[=<]\s*(\d+)\s*ms",
            r"time[=<]\s*([\d.]+)\s*ms",
        ]

        for pattern in patterns:

            match = re.search(
                pattern,
                output,
                re.IGNORECASE,
            )

            if match:
                return max(
                    1,
                    int(float(match.group(1)))
                )

        return None