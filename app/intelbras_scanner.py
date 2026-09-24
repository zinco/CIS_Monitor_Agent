"""Consultas de estado Intelbras CGI, sem alterar configurações do DVR."""

import re
import time
from datetime import datetime, timedelta
from urllib.parse import quote, urlencode

import requests
from requests.auth import HTTPDigestAuth


def _parse_properties(body: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in body.splitlines()
                if "=" in line and not line.lstrip().startswith("#"))


def _as_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    if value.lower() in ("true", "1"):
        return True
    if value.lower() in ("false", "0"):
        return False
    return None


def _as_mb(value: str | None) -> int | None:
    try:
        return max(0, int(float(value) / (1024 * 1024))) if value is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def parse_storage(body: str) -> list[dict]:
    fields = _parse_properties(body)
    indexes = sorted({int(index) for index in re.findall(r"list\.info\[(\d+)\]\.Name=", body)})
    disks = []
    for index in indexes[:64]:
        prefix = f"list.info[{index}]."
        state = fields.get(prefix + "State")
        partitions = sorted({int(partition) for partition in re.findall(
            re.escape(prefix) + r"Detail\[(\d+)\]\.IsError=", body)})
        partition_error = any(_as_bool(fields.get(prefix + f"Detail[{part}].IsError")) is True
                              for part in partitions)
        total = sum(_as_mb(fields.get(prefix + f"Detail[{part}].TotalBytes")) or 0
                    for part in partitions)
        used = sum(_as_mb(fields.get(prefix + f"Detail[{part}].UsedBytes")) or 0
                   for part in partitions)
        status = ("error" if state == "Error" or partition_error else
                  "ok" if state == "Success" else "unknown")
        disks.append({
            "id": index + 1,
            "name": fields.get(prefix + "Name") or f"HD {index + 1}",
            "disk_type": "Intelbras",
            "status": status,
            "capacity_mb": total or None,
            "free_space_mb": max(0, total - used) if total else None,
            "property": state,
        })
    return disks


def parse_camera_states(payload: dict) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    states = payload.get("states")
    if not isinstance(states, list):
        return []
    channels = []
    for item in states[:256]:
        if not isinstance(item, dict) or not isinstance(item.get("channel"), int):
            continue
        state = item.get("connectionState")
        channels.append({
            "channel": item["channel"] + 1,
            "signal_present": True if state == "Connected" else
                              False if state == "Unconnect" else None,
            "state": state,
        })
    return channels


def parse_recording_states(payload: dict) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    states = payload.get("state")
    if not isinstance(states, list):
        return []
    channels = []
    for index, item in enumerate(states[:256]):
        main = item.get("Main") if isinstance(item, dict) else None
        state = main.get("State") if isinstance(main, dict) else None
        status = "recording_now" if state == 1 else "not_recording" if state == 0 else "unknown"
        channels.append({
            "channel": index + 1,
            "recording_status": status,
            "recording_age_seconds": None,
            "last_recording_end": None,
        })
    return channels


def parse_record_modes(body: str) -> dict[int, int]:
    return {int(index) + 1: int(mode) for index, mode in re.findall(
        r"^table\.RecordMode\[(\d+)\]\.Mode=(\d+)\s*$", body, flags=re.MULTILINE)}


def parse_finder_end_times(body: str) -> list[datetime]:
    values = re.findall(r"^items\[\d+\]\.EndTime=([^\r\n]+)", body, flags=re.MULTILINE)
    result = []
    for value in values:
        try:
            result.append(datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            continue
    return result


class IntelbrasScanner:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def _request(self, ip_address: str, port: int, username: str, password: str,
                 path: str, *, body: dict | None = None,
                 params: dict | None = None) -> requests.Response:
        url = f"http://{ip_address}:{port}{path}"
        kwargs = {"auth": HTTPDigestAuth(username, password), "timeout": self.timeout}
        if body is None:
            encoded_params = urlencode(params, quote_via=quote) if params else None
            return requests.get(url, params=encoded_params, **kwargs)
        return requests.post(url, json=body, **kwargs)

    def get_storage(self, ip_address: str, port: int, username: str, password: str) -> dict:
        started = time.perf_counter()
        try:
            response = self._request(ip_address, port, username, password,
                                     "/cgi-bin/storageDevice.cgi?action=getDeviceAllInfo")
            disks = parse_storage(response.text) if response.ok else []
            resolved = response.ok and bool(disks)
            return {
                "supported": response.status_code not in (404, 405),
                "resolved": resolved,
                "healthy": (all(disk["status"] == "ok" for disk in disks)
                            if resolved and all(disk["status"] != "unknown" for disk in disks)
                            else None),
                "work_mode": None,
                "disks": disks,
                "message": (f"{len(disks)} HD(s) consultado(s)" if resolved else
                            f"Consulta de HD indisponível (HTTP {response.status_code})"),
                "status_code": response.status_code,
                "duration_ms": int((time.perf_counter() - started) * 1000),
            }
        except requests.RequestException:
            return {"supported": None, "resolved": False, "healthy": None, "work_mode": None,
                    "disks": [], "message": "Sem resposta na consulta de HD", "status_code": None,
                    "duration_ms": int((time.perf_counter() - started) * 1000)}

    def get_camera_states(self, ip_address: str, port: int, username: str, password: str) -> dict:
        started = time.perf_counter()
        try:
            response = self._request(ip_address, port, username, password,
                                     "/cgi-bin/api/LogicDeviceManager/getCameraState",
                                     body={"uniqueChannels": [-1]})
            channels = parse_camera_states(response.json()) if response.ok else []
            return {"source": "Intelbras CGI", "supported": response.status_code not in (404, 405),
                    "resolved": bool(channels), "channels": channels,
                    "message": (f"Conexão de {len(channels)} câmera(s) IP consultada" if channels else
                                f"Estado das câmeras indisponível (HTTP {response.status_code})"),
                    "status_code": response.status_code,
                    "duration_ms": int((time.perf_counter() - started) * 1000)}
        except (requests.RequestException, ValueError):
            return {"source": "Intelbras CGI", "supported": None, "resolved": False,
                    "channels": [], "message": "Sem resposta válida para estado das câmeras IP",
                    "status_code": None, "duration_ms": int((time.perf_counter() - started) * 1000)}

    def get_video_loss_events(self, ip_address: str, port: int, username: str, password: str) -> dict:
        started = time.perf_counter()
        try:
            response = self._request(ip_address, port, username, password,
                                     "/cgi-bin/eventManager.cgi?action=getEventIndexes&code=VideoLoss")
            fields = _parse_properties(response.text) if response.ok else {}
            channels = sorted({int(value) + 1 for key, value in fields.items()
                               if re.fullmatch(r"channels\[\d+\]", key) and value.isdigit()})
            resolved = response.ok and (response.text.strip() == "Error: No Events" or bool(re.search(
                r"^channels(?:\[\d+\])?=", response.text, flags=re.MULTILINE)))
            return {"supported": response.status_code not in (404, 405), "resolved": resolved,
                    "channels": channels, "status_code": response.status_code,
                    "duration_ms": int((time.perf_counter() - started) * 1000),
                    "message": (f"{len(channels)} canal(is) com evento de perda de vídeo ativo"
                                if resolved else f"Eventos de perda de vídeo indisponíveis (HTTP {response.status_code})")}
        except requests.RequestException:
            return {"supported": None, "resolved": False, "channels": [],
                    "status_code": None, "duration_ms": int((time.perf_counter() - started) * 1000),
                    "message": "Sem resposta para eventos de perda de vídeo"}

    def get_recording_states(self, ip_address: str, port: int, username: str, password: str) -> dict:
        started = time.perf_counter()
        try:
            response = self._request(ip_address, port, username, password,
                                     "/cgi-bin/api/recordManager/getStateAll", body={})
            channels = parse_recording_states(response.json()) if response.ok else []
            recording_now = sum(c["recording_status"] == "recording_now" for c in channels)
            return {"supported": response.status_code not in (404, 405, 501),
                    "resolved": bool(channels), "configured_channels": len(channels) if channels else None,
                    "channels_with_recent_recording": None, "channels_recording_now": recording_now,
                    "channels": channels, "device_local_time": None, "duration_ms": int((time.perf_counter() - started) * 1000),
                    "message": (f"{recording_now} de {len(channels)} canal(is) gravando agora; "
                                "gravações anteriores não foram verificadas" if channels else
                                f"Estado da gravação indisponível (HTTP {response.status_code})")}
        except (requests.RequestException, ValueError):
            return {"supported": None, "resolved": False, "configured_channels": None,
                    "channels_with_recent_recording": None, "channels_recording_now": None,
                    "channels": [], "device_local_time": None,
                    "duration_ms": int((time.perf_counter() - started) * 1000),
                    "message": "Sem resposta válida para estado de gravação"}

    def _device_time(self, ip_address: str, port: int, username: str, password: str) -> datetime | None:
        response = self._request(ip_address, port, username, password,
                                 "/cgi-bin/global.cgi?action=getCurrentTime")
        if not response.ok:
            return None
        value = _parse_properties(response.text).get("result")
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S") if value else None
        except ValueError:
            return None

    def _find_latest_recording(self, ip_address: str, port: int, username: str,
                               password: str, channel: int, now: datetime) -> datetime | None:
        path = "/cgi-bin/mediaFileFind.cgi"
        finder_id = None
        try:
            create = self._request(ip_address, port, username, password, path,
                                   params={"action": "factory.create"})
            if not create.ok:
                raise ValueError("Finder indisponível")
            finder_id = _parse_properties(create.text).get("result")
            if not finder_id or not re.fullmatch(r"[A-Za-z0-9]+", finder_id):
                raise ValueError("Identificador de pesquisa inválido")
            start = now - timedelta(minutes=30)
            find = self._request(ip_address, port, username, password, path, params={
                "action": "findFile", "object": finder_id, "condition.Channel": channel,
                "condition.StartTime": start.strftime("%Y-%m-%d %H:%M:%S"),
                "condition.EndTime": now.strftime("%Y-%m-%d %H:%M:%S"),
                "condition.Types[0]": "dav",
            })
            if not find.ok or find.text.strip() != "OK":
                raise ValueError("Pesquisa de gravações recusada")
            next_page = self._request(ip_address, port, username, password, path,
                                      params={"action": "findNextFile", "object": finder_id, "count": 100})
            if not next_page.ok:
                raise ValueError("Resultado da pesquisa indisponível")
            fields = _parse_properties(next_page.text)
            if "found" not in fields:
                raise ValueError("Quantidade de arquivos não informada")
            times = parse_finder_end_times(next_page.text)
            found = int(fields["found"])
            if found < 0 or (found > 0 and not times):
                raise ValueError("Horários das gravações não informados")
            return max(times) if times else None
        finally:
            if finder_id and re.fullmatch(r"[A-Za-z0-9]+", finder_id):
                for action in ("close", "destroy"):
                    try:
                        self._request(ip_address, port, username, password, path,
                                      params={"action": action, "object": finder_id})
                    except requests.RequestException:
                        pass

    def get_recent_recordings(self, ip_address: str, port: int, username: str,
                              password: str, *, sleep=time.sleep) -> dict:
        started = time.perf_counter()
        channels = []
        queries = 1
        try:
            now = self._device_time(ip_address, port, username, password)
            modes_response = self._request(ip_address, port, username, password,
                                           "/cgi-bin/configManager.cgi?action=getConfig&name=RecordMode")
            modes = parse_record_modes(modes_response.text) if modes_response.ok else {}
            if now is None or not modes:
                raise ValueError("Relógio ou canais de gravação indisponíveis")
            for channel, mode in sorted(modes.items())[:64]:
                item = {"channel": channel, "recording_status": "unknown",
                        "recording_age_seconds": None, "latest_recording": None,
                        "recording_mode": mode}
                if mode == 2:
                    item["recording_status"] = "disabled"
                else:
                    try:
                        latest = self._find_latest_recording(
                            ip_address, port, username, password, channel, now)
                        if latest is None:
                            item["recording_status"] = "no_recording"
                        else:
                            age = max(0, int((now - latest).total_seconds()))
                            item.update(recording_age_seconds=age,
                                        latest_recording=latest.strftime("%Y-%m-%d %H:%M:%S"),
                                        recording_status="within_tolerance" if age <= 180 else "pending_delay")
                    except (requests.RequestException, ValueError):
                        pass
                channels.append(item)

            pending = [item for item in channels if item["recording_status"] == "pending_delay"]
            if pending:
                sleep(20)
                queries = 2
                confirmed_at = self._device_time(ip_address, port, username, password)
                for item in pending:
                    if confirmed_at is None:
                        item["recording_status"] = "unknown"
                        continue
                    try:
                        latest = self._find_latest_recording(
                            ip_address, port, username, password, item["channel"], confirmed_at)
                        if latest is None:
                            item["recording_status"] = "no_recording"
                        else:
                            age = max(0, int((confirmed_at - latest).total_seconds()))
                            item.update(recording_age_seconds=age,
                                        latest_recording=latest.strftime("%Y-%m-%d %H:%M:%S"),
                                        recording_status="within_tolerance" if age <= 180 else "delayed")
                    except (requests.RequestException, ValueError):
                        item["recording_status"] = "unknown"

            if any(mode != 2 for mode in modes.values()) and all(
                item["recording_status"] in ("unknown", "disabled") for item in channels
            ):
                raise ValueError("Nenhum canal pôde ser consultado")
            recent = sum(item["recording_status"] == "within_tolerance" for item in channels)
            return {"supported": True, "resolved": True, "configured_channels": len(channels),
                    "channels_with_recent_recording": recent, "channels": channels,
                    "device_local_time": now.strftime("%Y-%m-%d %H:%M:%S"),
                    "delay_threshold_seconds": 180, "confirmation_checks": 2,
                    "confirmation_interval_seconds": 20, "queries_performed": queries,
                    "confirmation_completed": not any(item["recording_status"] == "pending_delay" for item in channels),
                    "duration_ms": int((time.perf_counter() - started) * 1000),
                    "message": f"{recent} de {len(channels)} canal(is) com gravação recente"}
        except (requests.RequestException, ValueError):
            return {"supported": None, "resolved": False, "configured_channels": None,
                    "channels_with_recent_recording": None, "channels": [],
                    "device_local_time": None, "duration_ms": int((time.perf_counter() - started) * 1000),
                    "message": "Busca de gravações não disponível neste equipamento"}

    def get_recordings(self, ip_address: str, port: int, username: str, password: str) -> dict:
        recent = self.get_recent_recordings(ip_address, port, username, password)
        if recent["resolved"]:
            return recent
        return self.get_recording_states(ip_address, port, username, password)
