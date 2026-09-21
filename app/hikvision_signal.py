"""Read video input status from Hikvision ISAPI without changing the DVR."""
import re
import time
import xml.etree.ElementTree as ET

import requests
from requests.auth import HTTPDigestAuth


def _name(tag):
    return tag.rsplit("}", 1)[-1]


def parse_video_inputs(content, allowed_channels=None):
    """Only explicit NO VIDEO or a reported resolution establishes signal."""
    root = ET.fromstring(content)
    channels = []
    allowed = set(allowed_channels) if allowed_channels is not None else None
    for element in root.iter():
        if _name(element.tag) != "VideoInputChannel":
            continue
        fields = {_name(child.tag): (child.text or "").strip()
                  for child in element}
        try:
            number = int(fields.get("id", ""))
        except ValueError:
            continue
        if allowed is not None and number not in allowed:
            continue
        description = fields.get("resDesc", "")
        if description.upper() == "NO VIDEO":
            present = False
        elif re.search(r"\d+\s*[*xX]\s*\d+", description):
            present = True
        else:
            continue
        channels.append({"channel": number, "signal_present": present})
    return sorted(channels, key=lambda channel: channel["channel"])


def read_isapi_video_signals(ip_address, username, password, port=80,
                             allowed_channels=None, timeout=5):
    started = time.perf_counter()
    result = {"source": "ISAPI", "supported": False, "resolved": False,
              "channels": [], "status_code": None,
              "message": "Estado de vídeo ISAPI indisponível"}
    host = ip_address if port == 80 else f"{ip_address}:{port}"
    try:
        response = requests.get(
            f"http://{host}/ISAPI/System/Video/inputs/channels",
            auth=HTTPDigestAuth(username, password), timeout=timeout,
        )
        result["status_code"] = response.status_code
        if response.status_code in (401, 403):
            result["message"] = "Autenticação ISAPI recusada"
        elif response.status_code == 404:
            result["message"] = "Estado de vídeo ISAPI não suportado"
        elif response.status_code != 200:
            result["message"] = f"Consulta de vídeo ISAPI retornou HTTP {response.status_code}"
        else:
            channels = parse_video_inputs(response.content, allowed_channels)
            expected = set(allowed_channels) if allowed_channels is not None else None
            complete = bool(channels) and (expected is None or
                         {item["channel"] for item in channels} == expected)
            result.update(supported=True, resolved=complete,
                          channels=channels,
                          message="Sinal de vídeo consultado por ISAPI" if complete
                                  else "ISAPI não informou o sinal de todos os canais")
    except requests.Timeout:
        result["message"] = "Tempo esgotado na consulta de vídeo ISAPI"
    except requests.RequestException:
        result["message"] = "Falha de conexão na consulta de vídeo ISAPI"
    except (ET.ParseError, ValueError):
        result["message"] = "Resposta de vídeo ISAPI inválida"
    result["duration_ms"] = int((time.perf_counter() - started) * 1000)
    return result
