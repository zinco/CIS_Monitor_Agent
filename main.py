import os
import socket
import time
from datetime import datetime

from dotenv import load_dotenv

from app.api_client import ApiClient
from app.ping_scanner import PingScanner
from app.tcp_scanner import TcpScanner

load_dotenv()


API_URL = os.getenv("LARAVEL_API_URL")
TOKEN = os.getenv("MONITORING_AGENT_TOKEN")

AGENT_HOSTNAME = os.getenv("AGENT_HOSTNAME") or socket.gethostname()

AGENT_VERSION = os.getenv(
    "AGENT_VERSION",
    "0.1.0",
)


def build_api_client() -> ApiClient:
    if not API_URL:
        raise RuntimeError("LARAVEL_API_URL não configurada.")

    if not TOKEN:
        raise RuntimeError("MONITORING_AGENT_TOKEN não configurado.")

    return ApiClient(
        base_url=API_URL,
        token=TOKEN,
    )


def run_cycle(
    api: ApiClient,
    ping_scanner: PingScanner,
    tcp_scanner: TcpScanner,
) -> int:

    print()
    print("=" * 60)
    print("Iniciando ciclo:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 60)

    # --------------------------------------------------
    # CONFIGURAÇÕES
    # --------------------------------------------------

    config = api.get_config()

    if not config["enabled"]:
        print("Monitoramento desabilitado " "nas configurações do Laravel.")

        return 60

    # --------------------------------------------------
    # HEARTBEAT
    # --------------------------------------------------

    heartbeat = api.send_heartbeat(
        hostname=AGENT_HOSTNAME,
        version=AGENT_VERSION,
    )

    print(f"Heartbeat OK - " f"Agente ID: {heartbeat['agent_id']}")

    # --------------------------------------------------
    # DISPOSITIVOS
    # --------------------------------------------------

    devices = api.get_devices()

    print(f"Dispositivos encontrados: " f"{len(devices)}")

    # --------------------------------------------------
    # PING HABILITADO?
    # --------------------------------------------------

    if not config["checks"]["ping"]:
        print("Verificação por ping está " "desabilitada.")

        return config["scan_interval_seconds"]

    # --------------------------------------------------
    # VERIFICAÇÃO INDIVIDUAL
    # --------------------------------------------------

    for device in devices:

        try:

            print()

            print(
                f"Verificando "
                f"{device['name']} "
                f"({device['ip_address']})..."
            )

            # --------------------------------------
            # VERIFICA DISPOSITIVO
            # --------------------------------------

            result = check_device(
                device=device,
                config=config,
                ping_scanner=ping_scanner,
                tcp_scanner=tcp_scanner,
            )

            # --------------------------------------
            # HORÁRIO
            # --------------------------------------

            checked_at = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            # --------------------------------------
            # PAYLOAD
            # --------------------------------------

            payload = {
                "device_id":
                    device["id"],

                "online":
                    result["online"],

                "latency_ms":
                    result["latency_ms"],

                "status": (
                    "healthy"
                    if result["online"]
                    else "offline"
                ),

                "status_message":
                    result["status_message"],

                "check_method":
                    result["check_method"],

                "duration_ms":
                    result["duration_ms"],

                "checked_at":
                    checked_at,
            }

            # --------------------------------------
            # ENVIA AO LARAVEL
            # --------------------------------------

            api.send_result(payload)

            # --------------------------------------
            # CONSOLE
            # --------------------------------------

            if result["online"]:

                if (
                    result["check_method"]
                    == "ping"
                ):

                    print(
                        f"ONLINE via PING - "
                        f"{result['latency_ms']} ms"
                    )

                else:

                    print(
                        f"ONLINE - "
                        f"{result['status_message']}"
                    )

            else:

                print(
                    f"OFFLINE - "
                    f"{result['status_message']}"
                )

        except Exception as error:

            print()

            print(
                f"ERRO ao verificar "
                f"{device['name']}: "
                f"{error}"
            )

            print(
                "Continuando para o próximo "
                "dispositivo..."
            )

            continue

            # ------------------------------------------
            # HORÁRIO DA VERIFICAÇÃO
            # ------------------------------------------

            checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # ------------------------------------------
            # PAYLOAD PARA O LARAVEL
            # ------------------------------------------

            payload = {
                "device_id": device["id"],
                "online": online,
                "latency_ms": latency_ms,
                "status": ("healthy" if online else "offline"),
                "status_message": status_message,
                "check_method": check_method,
                "duration_ms": duration_ms,
                "checked_at": checked_at,
            }

            # ------------------------------------------
            # ENVIA RESULTADO
            # ------------------------------------------

            api.send_result(payload)

            # ------------------------------------------
            # RESULTADO NO CONSOLE
            # ------------------------------------------

            if online:

                if check_method == "ping":

                    print(f"ONLINE via PING - " f"{latency_ms} ms")

                elif check_method == "tcp":

                    print(f"ONLINE via TCP - " f"{status_message}")

                else:

                    print("ONLINE")

            else:

                print(f"OFFLINE - " f"{status_message}")

        except Exception as error:

            print()

            print(f"ERRO ao verificar " f"{device['name']}: " f"{error}")

            print("Continuando para o próximo " "dispositivo...")

            continue

    # --------------------------------------------------
    # INTERVALO
    # --------------------------------------------------

    return config["scan_interval_seconds"]


def main():

    print()
    print("CIS Monitor Agent")
    print("-----------------")

    print(f"Hostname: {AGENT_HOSTNAME}")

    print(f"Versão: {AGENT_VERSION}")

    api = build_api_client()

    ping_scanner = PingScanner()

    tcp_scanner = TcpScanner()

    while True:

        try:

            interval = run_cycle(
                api,
                ping_scanner,
                tcp_scanner,
            )

            print()

            print(f"Próximo ciclo em " f"{interval} segundos.")

            time.sleep(interval)

        except KeyboardInterrupt:

            print()

            print("Encerrando CIS Monitor Agent...")

            break

        except Exception as error:

            print()

            print("Erro durante o ciclo:")

            print(error)

            print("Nova tentativa em 30 segundos.")

            time.sleep(30)


def check_device(
    device: dict,
    config: dict,
    ping_scanner: PingScanner,
    tcp_scanner: TcpScanner,
) -> dict:

    retry_attempts = max(1, int(config.get("retry_attempts", 1)))

    last_result = None

    for attempt in range(1, retry_attempts + 1):

        if retry_attempts > 1:
            print(f"  Tentativa " f"{attempt}/{retry_attempts}")

        # ------------------------------------------
        # PING
        # ------------------------------------------

        ping_result = ping_scanner.ping(
            ip_address=device["ip_address"],
            timeout_seconds=config["timeout_seconds"],
        )

        # Ping respondeu.
        if ping_result.online:

            return {
                "online": True,
                "latency_ms": ping_result.latency_ms,
                "duration_ms": ping_result.duration_ms,
                "check_method": "ping",
                "status_message": None,
            }

        # ------------------------------------------
        # FALLBACK TCP
        # ------------------------------------------

        ports = [
            device.get("http_port"),
            device.get("service_port"),
        ]

        tcp_result = tcp_scanner.check(
            ip_address=device["ip_address"],
            ports=ports,
            timeout_seconds=config["timeout_seconds"],
        )

        total_duration = ping_result.duration_ms + tcp_result.duration_ms

        # TCP respondeu.
        if tcp_result.online:

            return {
                "online": True,
                "latency_ms": None,
                "duration_ms": total_duration,
                "check_method": "tcp",
                "status_message": (f"Online via TCP porta " f"{tcp_result.port}"),
            }

        # ------------------------------------------
        # TENTATIVA FALHOU
        # ------------------------------------------

        last_result = {
            "online": False,
            "latency_ms": None,
            "duration_ms": total_duration,
            "check_method": "ping+tcp",
            "status_message": (f"Sem resposta após " f"{attempt} tentativa(s)"),
        }

        # Pequena pausa antes da próxima tentativa.
        if attempt < retry_attempts:

            print("  Sem resposta. " "Tentando novamente...")

            time.sleep(1)

    return last_result


if __name__ == "__main__":
    main()
