import os
import socket
import time
import threading

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from dotenv import load_dotenv
from app.onvif_scanner import OnvifScanner
from app.hikvision_scanner import HikvisionScanner
from app.full_diagnostics import collect_recordings
from app.hikvision_sdk import read_channel_signals
from app.hikvision_signal import read_isapi_video_signals
from app.api_client import ApiClient
from app.network_info_scanner import NetworkInfoScanner
from app.ping_scanner import PingScanner
from app.service_scanner import ServiceScanner
from app.tcp_scanner import TcpScanner


load_dotenv()


API_URL = os.getenv("LARAVEL_API_URL")
TOKEN = os.getenv("MONITORING_AGENT_TOKEN")

AGENT_HOSTNAME = os.getenv("AGENT_HOSTNAME") or socket.gethostname()

AGENT_VERSION = os.getenv(
    "AGENT_VERSION",
    "0.1.0",
)


# ==========================================================
# API CLIENT
# ==========================================================


def build_api_client() -> ApiClient:

    if not API_URL:
        raise RuntimeError(
            "LARAVEL_API_URL não configurada."
        )

    if not TOKEN:
        raise RuntimeError(
            "MONITORING_AGENT_TOKEN não configurado."
        )

    return ApiClient(
        base_url=API_URL,
        token=TOKEN,
    )


# ==========================================================
# VERIFICAÇÃO DE UM DISPOSITIVO
# ==========================================================


def check_device(
    device: dict,
    config: dict,
    ping_scanner: PingScanner,
    tcp_scanner: TcpScanner,
) -> dict:

    retry_attempts = max(
        1,
        int(config.get("retry_attempts", 1)),
    )

    last_result = None

    for attempt in range(
        1,
        retry_attempts + 1,
    ):

        print(
            f"[{device['name']}] "
            f"Tentativa "
            f"{attempt}/{retry_attempts}"
        )

        # --------------------------------------------------
        # PING
        # --------------------------------------------------

        ping_result = ping_scanner.ping(
            ip_address=device["ip_address"],
            timeout_seconds=config[
                "timeout_seconds"
            ],
        )

        # --------------------------------------------------
        # PING RESPONDEU
        # --------------------------------------------------

        if ping_result.online:

            return {
                "online": True,
                "latency_ms": (
                    ping_result.latency_ms
                ),
                "duration_ms": (
                    ping_result.duration_ms
                ),
                "check_method": "ping",
                "status_message": None,
            }

        # --------------------------------------------------
        # FALLBACK TCP
        # --------------------------------------------------

        ports = [
            device.get("http_port"),
            device.get("service_port"),
        ]

        tcp_result = tcp_scanner.check(
            ip_address=device["ip_address"],
            ports=ports,
            timeout_seconds=config[
                "timeout_seconds"
            ],
        )

        total_duration = (
            ping_result.duration_ms
            + tcp_result.duration_ms
        )

        # --------------------------------------------------
        # TCP RESPONDEU
        # --------------------------------------------------

        if tcp_result.online:

            return {
                "online": True,
                "latency_ms": None,
                "duration_ms": total_duration,
                "check_method": "tcp",
                "status_message": (
                    f"Online via TCP porta "
                    f"{tcp_result.port}"
                ),
            }

        # --------------------------------------------------
        # TENTATIVA FALHOU
        # --------------------------------------------------

        last_result = {
            "online": False,
            "latency_ms": None,
            "duration_ms": total_duration,
            "check_method": "ping+tcp",
            "status_message": (
                f"Sem resposta após "
                f"{attempt} tentativa(s)"
            ),
        }

        # --------------------------------------------------
        # NOVA TENTATIVA
        # --------------------------------------------------

        if attempt < retry_attempts:

            print(
                f"[{device['name']}] "
                f"Sem resposta. "
                f"Tentando novamente..."
            )

            time.sleep(1)

    return last_result


# ==========================================================
# PROCESSAMENTO COMPLETO DE UM DISPOSITIVO
# ==========================================================


def process_device(
    device: dict,
    config: dict,
    api: ApiClient,
    ping_scanner: PingScanner,
    tcp_scanner: TcpScanner,
) -> dict:

    result = check_device(
        device=device,
        config=config,
        ping_scanner=ping_scanner,
        tcp_scanner=tcp_scanner,
    )

    checked_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # --------------------------------------------------
    # PAYLOAD PARA O LARAVEL
    # --------------------------------------------------

    payload = {
        "device_id": device["id"],
        "online": result["online"],
        "latency_ms": result["latency_ms"],
        "status": (
            "healthy"
            if result["online"]
            else "offline"
        ),
        "status_message": (
            result["status_message"]
        ),
        "check_method": (
            result["check_method"]
        ),
        "duration_ms": (
            result["duration_ms"]
        ),
        "checked_at": checked_at,
    }

    # --------------------------------------------------
    # ENVIA RESULTADO
    # --------------------------------------------------

    api.send_result(payload)

    return {
        "device_id": device["id"],
        "device_name": device["name"],
        **result,
    }


# ==========================================================
# CICLO DE MONITORAMENTO
# ==========================================================


def run_cycle(
    api: ApiClient,
    ping_scanner: PingScanner,
    tcp_scanner: TcpScanner,
) -> int:

    print()
    print("=" * 60)

    print(
        "Iniciando ciclo:",
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
    )

    print("=" * 60)

    # --------------------------------------------------
    # CONFIGURAÇÕES
    # --------------------------------------------------

    config = api.get_config()

    if not config["enabled"]:

        print(
            "Monitoramento desabilitado "
            "nas configurações do Laravel."
        )

        return 60

    # --------------------------------------------------
    # HEARTBEAT
    # --------------------------------------------------

    heartbeat = api.send_heartbeat(
        hostname=AGENT_HOSTNAME,
        version=AGENT_VERSION,
    )

    print(
        f"Heartbeat OK - "
        f"Agente ID: "
        f"{heartbeat['agent_id']}"
    )

    # --------------------------------------------------
    # DISPOSITIVOS
    # --------------------------------------------------

    devices = api.get_devices()

    print(
        f"Dispositivos encontrados: "
        f"{len(devices)}"
    )

    # --------------------------------------------------
    # PING HABILITADO?
    # --------------------------------------------------

    if not config["checks"]["ping"]:

        print(
            "Verificação por ping está "
            "desabilitada."
        )

        return config[
            "scan_interval_seconds"
        ]

    # --------------------------------------------------
    # MAX WORKERS
    # --------------------------------------------------

    max_workers = max(
        1,
        int(
            config.get(
                "max_workers",
                10,
            )
        ),
    )

    print(
        f"Workers simultâneos: "
        f"{max_workers}"
    )

    print()

    # --------------------------------------------------
    # EXECUÇÃO CONCORRENTE
    # --------------------------------------------------

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:

        futures = {}

        for device in devices:

            future = executor.submit(
                process_device,
                device,
                config,
                api,
                ping_scanner,
                tcp_scanner,
            )

            futures[future] = device

        # --------------------------------------------------
        # RESULTADOS
        # --------------------------------------------------

        for future in as_completed(
            futures
        ):

            device = futures[future]

            try:

                result = future.result()

                # ------------------------------------------
                # ONLINE
                # ------------------------------------------

                if result["online"]:

                    if (
                        result[
                            "check_method"
                        ]
                        == "ping"
                    ):

                        print(
                            f"[ONLINE] "
                            f"{result['device_name']} - "
                            f"PING "
                            f"{result['latency_ms']} ms"
                        )

                    else:

                        print(
                            f"[ONLINE] "
                            f"{result['device_name']} - "
                            f"{result['status_message']}"
                        )

                # ------------------------------------------
                # OFFLINE
                # ------------------------------------------

                else:

                    print(
                        f"[OFFLINE] "
                        f"{result['device_name']} - "
                        f"{result['status_message']}"
                    )

            except Exception as error:

                print(
                    f"[ERRO] "
                    f"{device['name']} - "
                    f"{error}"
                )

    # --------------------------------------------------
    # INTERVALO
    # --------------------------------------------------

    return config[
        "scan_interval_seconds"
    ]


# ==========================================================
# SCANNER MANUAL
# ==========================================================


def process_scan_job(
    job: dict,
    api: ApiClient,
    ping_scanner: PingScanner,
    tcp_scanner: TcpScanner,
    network_info_scanner: NetworkInfoScanner,
    service_scanner: ServiceScanner,
    onvif_scanner: OnvifScanner,
    hikvision_scanner: HikvisionScanner,
):

    job_id = job["id"]
    target_ip = job["target_ip"]
    ports = job.get("ports") or []
    detailed_diagnostics = job.get("detailed_diagnostics") is True
    diagnostic_port = int(job.get("diagnostic_port") or 80)

    print()

    print(
        f"[SCANNER] Job #{job_id} - "
        f"Testando {target_ip}"
    )

    started = time.perf_counter()

    try:

        # --------------------------------------------------
        # HOSTNAME
        # --------------------------------------------------

        hostname_result = (
            network_info_scanner.resolve_hostname(
                target_ip
            )
        )

        # --------------------------------------------------
        # PING
        # --------------------------------------------------

        ping_result = ping_scanner.ping(
            ip_address=target_ip,
            timeout_seconds=3,
        )

        # --------------------------------------------------
        # MAC / ARP
        # --------------------------------------------------

        mac_result = (
            network_info_scanner
            .resolve_mac_address(
                target_ip
            )
        )

        # --------------------------------------------------
        # FABRICANTE / OUI
        # --------------------------------------------------

        vendor_result = (
            network_info_scanner
            .resolve_vendor(
                mac_result.mac_address
            )
        )

        # --------------------------------------------------
        # LOG REDE
        # --------------------------------------------------

        if vendor_result.resolved:

            print(
                f"[SCANNER] Fabricante: "
                f"{vendor_result.vendor}"
            )

        else:

            print(
                "[SCANNER] Fabricante "
                "não identificado"
            )

        if hostname_result.resolved:

            print(
                f"[SCANNER] Hostname: "
                f"{hostname_result.hostname}"
            )

        else:

            print(
                "[SCANNER] Hostname "
                "não identificado"
            )

        if mac_result.resolved:

            print(
                f"[SCANNER] MAC: "
                f"{mac_result.mac_address}"
            )

        else:

            print(
                "[SCANNER] MAC "
                "não identificado"
            )

        # --------------------------------------------------
        # TODAS AS PORTAS TCP
        # --------------------------------------------------

        port_results = (
            tcp_scanner.scan_ports(
                ip_address=target_ip,
                ports=ports,
                timeout_seconds=3,
            )
        )

        ports_data = []

        open_ports = []

        for port_result in port_results:

            ports_data.append(
                {
                    "port": (
                        port_result.port
                    ),
                    "open": (
                        port_result.open
                    ),
                    "duration_ms": (
                        port_result.duration_ms
                    ),
                    "message": (
                        port_result.message
                    ),
                }
            )

            if port_result.open:

                open_ports.append(
                    port_result.port
                )

        # --------------------------------------------------
        # SERVIÇOS HTTP / HTTPS
        # --------------------------------------------------

        http_services = []

        for port in open_ports:

            if port not in (
                80,
                443,
            ):
                continue

            http_result = (
                service_scanner.scan_http(
                    target_ip,
                    port,
                )
            )

            http_services.append(
                {
                    "port": (
                        http_result.port
                    ),
                    "scheme": (
                        http_result.scheme
                    ),
                    "detected": (
                        http_result.detected
                    ),
                    "status_code": (
                        http_result.status_code
                    ),
                    "server": (
                        http_result.server
                    ),
                    "title": (
                        http_result.title
                    ),
                    "duration_ms": (
                        http_result.duration_ms
                    ),
                    "message": (
                        http_result.message
                    ),
                }
            )

            if http_result.detected:

                print(
                    f"[SCANNER] "
                    f"{http_result.scheme.upper()} "
                    f"{port}: "
                    f"{http_result.status_code} "
                    f"{http_result.title or ''}"
                )
        # --------------------------------------------------
        # SERVIÇOS RTSP
        # --------------------------------------------------

        rtsp_services = []

        for port in open_ports:

            if port != 554:
                continue

            rtsp_result = service_scanner.scan_rtsp(
                target_ip,
                port,
            )

            rtsp_services.append(
                {
                    "port": rtsp_result.port,
                    "detected": rtsp_result.detected,
                    "status_code": rtsp_result.status_code,
                    "status_text": rtsp_result.status_text,
                    "server": rtsp_result.server,
                    "public_methods": rtsp_result.public_methods,
                    "duration_ms": rtsp_result.duration_ms,
                    "message": rtsp_result.message,
                }
            )

            if rtsp_result.detected:
                print(
                    f"[SCANNER] RTSP "
                    f"{port}: "
                    f"{rtsp_result.status_code} "
                    f"{rtsp_result.status_text or ''}"
                )

        # --------------------------------------------------
        # ONVIF
        # --------------------------------------------------

        onvif_result = onvif_scanner.detect(
            target_ip,
            ports=[diagnostic_port] if job.get("diagnostic_port") else None,
        )

        if onvif_result.detected:

            print(
                f"[SCANNER] ONVIF "
                f"{onvif_result.port}: "
                f"{onvif_result.status_code}"
            )

        else:

            print(
                "[SCANNER] ONVIF não identificado"
            )

        # --------------------------------------------------
        # INFORMAÇÕES ONVIF AUTENTICADAS
        # --------------------------------------------------
        #
        # As credenciais chegam somente no Job recebido
        # pela API. Elas são usadas apenas em memória e
        # nunca são impressas nem incluídas no resultado.
        # --------------------------------------------------

        onvif_device_info = None

        onvif_config = (
            job.get("onvif")
            or {}
        )

        onvif_enabled = (
            onvif_config.get("enabled")
            is True
        )

        onvif_username = (
            onvif_config.get("username")
        )

        onvif_password = (
            onvif_config.get("password")
        )

        if (
            onvif_enabled
            and onvif_result.detected
            and onvif_result.port is not None
            and onvif_username
            and onvif_password
        ):

            onvif_device_info = (
                onvif_scanner
                .get_device_information(
                    ip_address=target_ip,
                    username=onvif_username,
                    password=onvif_password,
                    port=onvif_result.port,
                )
            )

            if onvif_device_info.resolved:

                print(
                    "[SCANNER] ONVIF autenticado: "
                    "informações do equipamento "
                    "identificadas"
                )

                if onvif_device_info.manufacturer:
                    print(
                        f"[SCANNER] Fabricante ONVIF: "
                        f"{onvif_device_info.manufacturer}"
                    )

                if onvif_device_info.model:
                    print(
                        f"[SCANNER] Modelo ONVIF: "
                        f"{onvif_device_info.model}"
                    )

            else:

                print(
                    "[SCANNER] ONVIF autenticado: "
                    f"{onvif_device_info.message or 'informações não identificadas'}"
                )

        elif onvif_enabled and not onvif_result.detected:

            print(
                "[SCANNER] Autenticação ONVIF solicitada, "
                "mas o serviço ONVIF não foi identificado"
            )

        elif (
            onvif_enabled
            and (
                not onvif_username
                or not onvif_password
            )
        ):

            print(
                "[SCANNER] Autenticação ONVIF solicitada, "
                "mas as credenciais não foram recebidas"
            )

        # --------------------------------------------------
        # DIAGNÓSTICO DETALHADO
        # --------------------------------------------------

        diagnostics = None

        if detailed_diagnostics:

            print(
                "[SCANNER] Diagnóstico detalhado solicitado"
            )

            manufacturer = None

            if (
                onvif_device_info is not None
                and onvif_device_info.resolved
            ):
                manufacturer = (
                    onvif_device_info.manufacturer
                )

            is_hikvision = (
                manufacturer is not None
                and "hikvision"
                in manufacturer.lower()
            )

            sdk_signals = None
            # ONVIF pode rejeitar uma conta enquanto o protocolo nativo
            # aceita o login. Uma leitura SDK bem-sucedida identifica o DVR.
            if (
                onvif_username
                and onvif_password
                and (is_hikvision or 8000 in open_ports)
            ):
                sdk_signals = read_channel_signals(
                    target_ip, onvif_username, onvif_password,
                    port=int(job.get("service_port") or 8000),
                )
                if sdk_signals.get("identified"):
                    is_hikvision = True

            if (
                is_hikvision
                and onvif_username
                and onvif_password
            ):

                print(
                    "[SCANNER] Executando diagnóstico "
                    "Hikvision"
                )

                storage_result = (
                    hikvision_scanner.get_storage(
                        ip_address=target_ip,
                        username=onvif_username,
                        password=onvif_password,
                        port=diagnostic_port,
                    )
                )

                diagnostics = {
                    "manufacturer": "hikvision",
                    "storage": (
                        storage_result.to_dict()
                    ),
                }

                # HCNetSDK consulta somente o estado de trabalho do DVR.
                # A porta SDK e independente da porta HTTP usada pela ISAPI.
                diagnostics["signals"] = sdk_signals

                if storage_result.resolved:

                    print(
                        "[SCANNER] Armazenamento: "
                        f"{storage_result.message}"
                    )

                    for disk in storage_result.disks:

                        print(
                            f"[SCANNER] HD {disk.id}: "
                            f"{disk.status} - "
                            f"{disk.capacity_mb} MB - "
                            f"{disk.property}"
                        )

                else:

                    print(
                        "[SCANNER] Armazenamento: "
                        f"{storage_result.message}"
                    )

                # Consulta recente por canal somente no diagnostico detalhado.
                # Cada job confirma atrasos sem usar evidencias de jobs anteriores.
                try:
                    recordings = collect_recordings(
                        ip_address=target_ip,
                        username=onvif_username,
                        password=onvif_password,
                        port=diagnostic_port,
                    )
                    diagnostics["recordings"] = recordings
                    if not diagnostics["signals"]["resolved"]:
                        channel_numbers = [
                            channel["channel"] for channel in recordings["channels"]
                            if channel.get("channel") is not None
                        ]
                        isapi_signals = read_isapi_video_signals(
                            target_ip, onvif_username, onvif_password,
                            port=diagnostic_port,
                            allowed_channels=channel_numbers or None,
                        )
                        if isapi_signals["channels"]:
                            diagnostics["signals"] = isapi_signals
                        else:
                            diagnostics["signals"]["isapi_message"] = (
                                isapi_signals["message"]
                            )
                    print(f"[SCANNER] Gravacoes: {recordings['message']}")
                    for channel in recordings["channels"]:
                        print(
                            f"[SCANNER] Canal {channel['channel']}: "
                            f"{channel['recording_status']} - "
                            f"atraso: {channel['recording_age_seconds']} s"
                        )
                except Exception:
                    # Preserva o resultado do HD se a nova consulta falhar.
                    # Nao inclui detalhes da excecao que possam conter segredos.
                    diagnostics["recordings"] = {
                        "supported": None,
                        "resolved": False,
                        "configured_channels": None,
                        "channels_with_recent_recording": None,
                        "channels": [],
                        "device_local_time": None,
                        "duration_ms": None,
                        "delay_threshold_seconds": 180,
                        "confirmation_checks": 2,
                        "message": "Erro ao executar diagnostico de gravacao",
                    }
                    print("[SCANNER] Diagnostico de gravacao nao concluido")

            elif not is_hikvision:

                authentication_failed = (
                    onvif_device_info is not None
                    and onvif_device_info.status_code in (401, 403)
                )

                diagnostics = {
                    "manufacturer": (
                        manufacturer
                    ),
                    "storage": None,
                    "signals": sdk_signals,
                    "message": (
                        "Autenticação ONVIF recusada; fabricante não identificado. "
                        "Confira a conta do DVR e as permissões de acesso remoto."
                        if authentication_failed else
                        "Fabricante não identificado; diagnóstico detalhado indisponível"
                    ),
                }

                print(
                    "[SCANNER] Diagnóstico detalhado: "
                    "fabricante ainda não suportado"
                )

            else:

                diagnostics = {
                    "manufacturer": "hikvision",
                    "storage": None,
                    "message": (
                        "Credenciais não disponíveis "
                        "para o diagnóstico detalhado"
                    ),
                }

                print(
                    "[SCANNER] Diagnóstico Hikvision: "
                    "credenciais não disponíveis"
                )

        # --------------------------------------------------
        # DURAÇÃO TOTAL
        # --------------------------------------------------

        duration_ms = int(
            (
                time.perf_counter()
                - started
            )
            * 1000
        )

        # --------------------------------------------------
        # EQUIPAMENTO ONLINE?
        # --------------------------------------------------
        #
        # Consideramos online se:
        #
        # - respondeu ao ping
        # OU
        # - pelo menos uma porta TCP respondeu
        #
        # Isso é importante porque algumas câmeras
        # bloqueiam ICMP mas continuam funcionando.
        #
        # --------------------------------------------------

        online = (
            ping_result.online
            or len(open_ports) > 0
        )

        # --------------------------------------------------
        # MÉTODO
        # --------------------------------------------------

        if (
            ping_result.online
            and open_ports
        ):

            check_method = "ping+tcp"

        elif ping_result.online:

            check_method = "ping"

        elif open_ports:

            check_method = "tcp"

        else:

            check_method = "ping+tcp"

        # --------------------------------------------------
        # MENSAGEM
        # --------------------------------------------------

        if online:

            if open_ports:

                open_ports_text = (
                    ", ".join(
                        str(port)
                        for port in open_ports
                    )
                )

                status_message = (
                    "Equipamento online. "
                    f"Portas abertas: "
                    f"{open_ports_text}."
                )

            else:

                status_message = (
                    "Equipamento respondeu "
                    "ao ping, "
                    "mas nenhuma das portas "
                    "informadas respondeu."
                )

        else:

            status_message = (
                "Equipamento não respondeu "
                "ao ping nem às portas TCP "
                "testadas."
            )

        # --------------------------------------------------
        # PAYLOAD
        # --------------------------------------------------

        payload = {
            "status": "completed",
            "online": online,
            "latency_ms": (
                ping_result.latency_ms
                if ping_result.online
                else None
            ),
            "duration_ms": duration_ms,
            "check_method": check_method,
            "status_message": (
                status_message
            ),
            "result": {
                "diagnostics": diagnostics,

                "network": {
                    "hostname": (
                        hostname_result.hostname
                    ),
                    "hostname_resolved": (
                        hostname_result.resolved
                    ),
                    "duration_ms": (
                        hostname_result.duration_ms
                    ),
                    "message": (
                        hostname_result.message
                    ),

                    "mac_address": (
                        mac_result.mac_address
                    ),
                    "mac_resolved": (
                        mac_result.resolved
                    ),
                    "mac_duration_ms": (
                        mac_result.duration_ms
                    ),
                    "mac_message": (
                        mac_result.message
                    ),

                    "vendor": (
                        vendor_result.vendor
                    ),
                    "vendor_resolved": (
                        vendor_result.resolved
                    ),
                    "vendor_prefix": (
                        vendor_result.prefix
                    ),
                    "vendor_message": (
                        vendor_result.message
                    ),
                },

                "ping": {
                    "online": (
                        ping_result.online
                    ),
                    "latency_ms": (
                        ping_result.latency_ms
                    ),
                    "duration_ms": (
                        ping_result.duration_ms
                    ),
                    "message": (
                        ping_result.message
                    ),
                },

                "tcp": {
                    "ports": ports_data,
                    "open_ports": (
                        open_ports
                    ),
                },

            "services": {
                    "http": (
                        http_services
                    ),
                    "rtsp": (
                        rtsp_services
                    ),
                    "onvif": {
                        "detected": onvif_result.detected,
                        "port": onvif_result.port,
                        "status_code": onvif_result.status_code,
                        "endpoint": onvif_result.endpoint,
                        "duration_ms": onvif_result.duration_ms,
                        "message": onvif_result.message,

                        "authenticated": (
                            onvif_device_info is not None
                            and onvif_device_info.resolved
                        ),

                        "device_information": (
                            {
                                "resolved": (
                                    onvif_device_info.resolved
                                ),
                                "manufacturer": (
                                    onvif_device_info.manufacturer
                                ),
                                "model": (
                                    onvif_device_info.model
                                ),
                                "firmware_version": (
                                    onvif_device_info.firmware_version
                                ),
                                "serial_number": (
                                    onvif_device_info.serial_number
                                ),
                                "hardware_id": (
                                    onvif_device_info.hardware_id
                                ),
                                "status_code": (
                                    onvif_device_info.status_code
                                ),
                                "duration_ms": (
                                    onvif_device_info.duration_ms
                                ),
                                "message": (
                                    onvif_device_info.message
                                ),
                            }
                            if onvif_device_info is not None
                            else None
                        ),
                    },
                },
            },
        }

        # --------------------------------------------------
        # ENVIA RESULTADO
        # --------------------------------------------------

        api.send_scan_job_result(
            job_id,
            payload,
        )

        # --------------------------------------------------
        # LOG FINAL
        # --------------------------------------------------

        if online:

            print(
                f"[SCANNER] "
                f"Job #{job_id} - "
                f"ONLINE"
            )

            if ping_result.online:

                print(
                    f"[SCANNER] Ping: "
                    f"{ping_result.latency_ms} ms"
                )

            if open_ports:

                print(
                    f"[SCANNER] "
                    f"Portas abertas: "
                    f"{open_ports}"
                )

            else:

                print(
                    "[SCANNER] Nenhuma porta "
                    "TCP respondeu."
                )

        else:

            print(
                f"[SCANNER] "
                f"Job #{job_id} - "
                f"OFFLINE"
            )

    except Exception as error:

        print(
            f"[SCANNER] "
            f"Job #{job_id} - "
            f"ERRO: {error}"
        )

        try:

            api.send_scan_job_result(
                job_id,
                {
                    "status": "failed",
                    "online": None,
                    "error_message": (
                        str(error)
                    ),
                    "status_message": (
                        "Erro durante execução "
                        "do Scanner."
                    ),
                },
            )

        except Exception as send_error:

            print(
                f"[SCANNER] "
                f"Não foi possível "
                f"enviar o erro do Job "
                f"#{job_id}: "
                f"{send_error}"
            )


# ==========================================================
# LOOP DO SCANNER MANUAL
# ==========================================================


def scanner_loop(
    api: ApiClient,
    ping_scanner: PingScanner,
    tcp_scanner: TcpScanner,
    network_info_scanner: NetworkInfoScanner,
    service_scanner: ServiceScanner,
    onvif_scanner: OnvifScanner,
    hikvision_scanner: HikvisionScanner,
):

    print(
        "[SCANNER] Scanner manual iniciado "
        "(consulta a cada 2 segundos)."
    )

    while True:

        try:

            job = (
                api.get_next_scan_job()
            )

            if job is None:

                time.sleep(2)
                continue

            process_scan_job(
                job=job,
                api=api,
                ping_scanner=ping_scanner,
                tcp_scanner=tcp_scanner,
                network_info_scanner=(
                    network_info_scanner
                ),
                service_scanner=(
                    service_scanner
                ),
                onvif_scanner=(
                    onvif_scanner
                ),
                hikvision_scanner=hikvision_scanner,
            )

            # Não dorme aqui.
            # Se houver outro job pendente,
            # busca imediatamente.

        except Exception as error:

            print(
                f"[SCANNER] "
                f"Erro ao consultar "
                f"trabalhos: {error}"
            )

            time.sleep(5)


# ==========================================================
# MAIN
# ==========================================================


def main():

    print()

    print(
        "CIS Monitor Agent"
    )

    print(
        "-----------------"
    )

    print(
        f"Hostname: "
        f"{AGENT_HOSTNAME}"
    )

    print(
        f"Versão: "
        f"{AGENT_VERSION}"
    )

    api = build_api_client()

    ping_scanner = PingScanner()

    tcp_scanner = TcpScanner()
    
    onvif_scanner = OnvifScanner()
    hikvision_scanner = HikvisionScanner()

    network_info_scanner = (
        NetworkInfoScanner()
    )

    service_scanner = (
        ServiceScanner()
    )

    # --------------------------------------------------
    # SCANNER MANUAL
    # --------------------------------------------------

    scanner_thread = (
        threading.Thread(
            target=scanner_loop,
            args=(
                api,
                ping_scanner,
                tcp_scanner,
                network_info_scanner,
                service_scanner,
                onvif_scanner,
                hikvision_scanner,
            ),
            daemon=True,
        )
    )

    scanner_thread.start()

    # --------------------------------------------------
    # LOOP PRINCIPAL
    # --------------------------------------------------

    while True:

        try:

            interval = run_cycle(
                api,
                ping_scanner,
                tcp_scanner,
            )

            print()

            print(
                f"Próximo ciclo em "
                f"{interval} segundos."
            )

            time.sleep(
                interval
            )

        except KeyboardInterrupt:

            print()

            print(
                "Encerrando "
                "CIS Monitor Agent..."
            )

            break

        except Exception as error:

            print()

            print(
                "Erro durante o ciclo:"
            )

            print(
                error
            )

            print(
                "Nova tentativa em "
                "30 segundos."
            )

            time.sleep(30)


# ==========================================================
# START
# ==========================================================


if __name__ == "__main__":
    main()
