from dataclasses import asdict, dataclass

from datetime import datetime, timedelta

import time

import uuid

import xml.etree.ElementTree as ET


import requests

from requests.auth import HTTPDigestAuth


# ============================================================

# ARMAZENAMENTO

# ============================================================


@dataclass

class HikvisionDisk:

    id: int | None

    name: str | None

    disk_type: str | None

    status: str | None

    capacity_mb: int | None

    free_space_mb: int | None

    property: str | None


    def to_dict(self) -> dict:

        return asdict(self)


@dataclass

class HikvisionStorageResult:

    supported: bool

    resolved: bool

    healthy: bool | None

    work_mode: str | None

    disks: list[HikvisionDisk]

    message: str

    status_code: int | None

    duration_ms: int


    def to_dict(self) -> dict:

        return {

            "supported": self.supported,

            "resolved": self.resolved,

            "healthy": self.healthy,

            "work_mode": self.work_mode,

            "disks": [

                disk.to_dict()

                for disk in self.disks

            ],

            "message": self.message,

            "status_code": self.status_code,

            "duration_ms": self.duration_ms,

        }


# ============================================================

# TRACKS DE GRAVAÇÃO

# ============================================================


@dataclass

class HikvisionRecordingTrack:

    track_id: int | None

    channel_id: int | None

    source_channel: int | None


    enabled: bool

    schedule_enabled: bool

    record_enabled: bool


    recording_mode: str | None

    description: str | None

    source_url: str | None


    def to_dict(self) -> dict:

        return asdict(self)


@dataclass

class HikvisionRecordingTracksResult:

    supported: bool

    resolved: bool

    tracks: list[HikvisionRecordingTrack]

    enabled_tracks: int

    recording_tracks: int

    message: str

    status_code: int | None

    duration_ms: int


    def to_dict(self) -> dict:

        return {

            "supported": self.supported,

            "resolved": self.resolved,

            "tracks": [

                track.to_dict()

                for track in self.tracks

            ],

            "enabled_tracks": self.enabled_tracks,

            "recording_tracks": self.recording_tracks,

            "message": self.message,

            "status_code": self.status_code,

            "duration_ms": self.duration_ms,

        }


# ============================================================

# PESQUISA DE GRAVAÇÕES

# ============================================================


@dataclass

class HikvisionRecordingSegment:

    track_id: int | None

    start_time: str | None

    end_time: str | None

    content_type: str | None

    codec_type: str | None

    recording_type: str | None


    def to_dict(self) -> dict:

        return asdict(self)


@dataclass

class HikvisionRecordingResult:

    supported: bool

    resolved: bool

    recording_found: bool

    track_id: int

    num_of_matches: int

    has_more: bool

    first_recording: str | None

    latest_recording: str | None

    segments: list[HikvisionRecordingSegment]

    message: str

    status_code: int | None

    duration_ms: int


    def to_dict(self) -> dict:

        return {

            "supported": self.supported,

            "resolved": self.resolved,

            "recording_found": self.recording_found,

            "track_id": self.track_id,

            "num_of_matches": self.num_of_matches,

            "has_more": self.has_more,

            "first_recording": self.first_recording,

            "latest_recording": self.latest_recording,

            "segments": [

                segment.to_dict()

                for segment in self.segments

            ],

            "message": self.message,

            "status_code": self.status_code,

            "duration_ms": self.duration_ms,

        }


# ============================================================

# DIAGNÓSTICO DE GRAVAÇÃO

# ============================================================


@dataclass

class HikvisionRecordingDiagnostics:

    supported: bool

    resolved: bool

    recording_found: bool

    track_id: int

    first_recording: str | None

    latest_recording: str | None

    history_days: float | None

    recent_recording_found: bool

    message: str

    duration_ms: int


    def to_dict(self) -> dict:

        return asdict(self)


# ============================================================
# RELÓGIO DO EQUIPAMENTO
# ============================================================

@dataclass
class HikvisionDeviceTimeResult:
    supported: bool
    resolved: bool
    time_mode: str | None
    local_time: str | None
    timezone: str | None
    message: str
    status_code: int | None
    duration_ms: int

    def to_dict(self) -> dict:
        return asdict(self)


# ============================================================
# DIAGNÓSTICO RECENTE POR CANAL
# ============================================================

@dataclass
class HikvisionChannelRecordingDiagnostic:
    channel: int | None
    track_id: int | None
    configured: bool
    enabled: bool
    schedule_enabled: bool
    record_enabled: bool
    resolved: bool
    recording_found: bool
    latest_recording: str | None
    num_of_matches: int
    has_more: bool
    message: str
    duration_ms: int
    recording_age_seconds: float | None = None
    recording_status: str = "unknown"
    consecutive_delayed_checks: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HikvisionChannelsRecordingDiagnostics:
    supported: bool
    resolved: bool
    configured_channels: int
    channels_with_recent_recording: int
    channels: list[HikvisionChannelRecordingDiagnostic]
    message: str
    duration_ms: int
    device_local_time: str | None = None

    def to_dict(self) -> dict:
        return {
            "device_local_time": self.device_local_time,
            "supported": self.supported,
            "resolved": self.resolved,
            "configured_channels": self.configured_channels,
            "channels_with_recent_recording": (
                self.channels_with_recent_recording
            ),
            "channels": [
                channel.to_dict()
                for channel in self.channels
            ],
            "message": self.message,
            "duration_ms": self.duration_ms,
        }


# ============================================================

# SCANNER HIKVISION

# ============================================================


class HikvisionScanner:

    def __init__(

        self,

        timeout_seconds: float = 5.0,

    ):

        self.timeout_seconds = timeout_seconds
        # Historico em memoria; reutilize esta instancia entre consultas.
        self._recording_delay_history: dict = {}


    # ========================================================

    # ARMAZENAMENTO

    # ========================================================


    def get_storage(

        self,

        ip_address: str,

        username: str,

        password: str,

        port: int = 80,

        use_https: bool = False,

    ) -> HikvisionStorageResult:

        started = time.perf_counter()


        scheme = "https" if use_https else "http"


        host = self._build_host(

            ip_address=ip_address,

            port=port,

            use_https=use_https,

        )


        url = (

            f"{scheme}://{host}"

            "/ISAPI/ContentMgmt/Storage"

        )


        try:

            response = requests.get(

                url,

                auth=HTTPDigestAuth(

                    username,

                    password,

                ),

                timeout=self.timeout_seconds,

                verify=False,

            )


            duration_ms = self._duration_ms(started)


            if response.status_code in (401, 403):

                return HikvisionStorageResult(

                    supported=True,

                    resolved=False,

                    healthy=None,

                    work_mode=None,

                    disks=[],

                    message=(

                        "Falha de autenticação "

                        "na ISAPI Hikvision"

                    ),

                    status_code=response.status_code,

                    duration_ms=duration_ms,

                )


            if response.status_code == 404:

                return HikvisionStorageResult(

                    supported=False,

                    resolved=False,

                    healthy=None,

                    work_mode=None,

                    disks=[],

                    message=(

                        "Consulta de armazenamento "

                        "não suportada"

                    ),

                    status_code=404,

                    duration_ms=duration_ms,

                )


            response.raise_for_status()


            root = ET.fromstring(

                response.content

            )


            work_mode = self._find_text(

                root,

                "workMode",

            )


            disks: list[HikvisionDisk] = []


            for element in root.iter():

                if (

                    self._local_name(element.tag)

                    != "hdd"

                ):

                    continue


                disk = HikvisionDisk(

                    id=self._to_int(

                        self._find_text(

                            element,

                            "id",

                        )

                    ),

                    name=self._find_text(

                        element,

                        "hddName",

                    ),

                    disk_type=self._find_text(

                        element,

                        "hddType",

                    ),

                    status=self._find_text(

                        element,

                        "status",

                    ),

                    capacity_mb=self._to_int(

                        self._find_text(

                            element,

                            "capacity",

                        )

                    ),

                    free_space_mb=self._to_int(

                        self._find_text(

                            element,

                            "freeSpace",

                        )

                    ),

                    property=self._find_text(

                        element,

                        "property",

                    ),

                )


                disks.append(disk)


            if not disks:

                return HikvisionStorageResult(

                    supported=True,

                    resolved=True,

                    healthy=False,

                    work_mode=work_mode,

                    disks=[],

                    message="Nenhum HD identificado",

                    status_code=response.status_code,

                    duration_ms=duration_ms,

                )


            healthy = all(

                self._disk_is_healthy(disk)

                for disk in disks

            )


            if healthy:

                message = (

                    "Armazenamento identificado "

                    "e operacional"

                )

            else:

                message = (

                    "Um ou mais HDs apresentam "

                    "estado de atenção"

                )


            return HikvisionStorageResult(

                supported=True,

                resolved=True,

                healthy=healthy,

                work_mode=work_mode,

                disks=disks,

                message=message,

                status_code=response.status_code,

                duration_ms=duration_ms,

            )


        except requests.RequestException as error:

            return HikvisionStorageResult(

                supported=False,

                resolved=False,

                healthy=None,

                work_mode=None,

                disks=[],

                message=(

                    "Erro ao consultar armazenamento: "

                    f"{error}"

                ),

                status_code=None,

                duration_ms=self._duration_ms(

                    started

                ),

            )


        except ET.ParseError:

            return HikvisionStorageResult(

                supported=True,

                resolved=False,

                healthy=None,

                work_mode=None,

                disks=[],

                message="Resposta ISAPI inválida",

                status_code=None,

                duration_ms=self._duration_ms(

                    started

                ),

            )


    # ========================================================

    # TRACKS

    # ========================================================


    def get_recording_tracks(

        self,

        ip_address: str,

        username: str,

        password: str,

        port: int = 80,

        use_https: bool = False,

    ) -> HikvisionRecordingTracksResult:

        started = time.perf_counter()


        scheme = "https" if use_https else "http"


        host = self._build_host(

            ip_address=ip_address,

            port=port,

            use_https=use_https,

        )


        url = (

            f"{scheme}://{host}"

            "/ISAPI/ContentMgmt/record/tracks"

        )


        try:

            response = requests.get(

                url,

                auth=HTTPDigestAuth(

                    username,

                    password,

                ),

                timeout=self.timeout_seconds,

                verify=False,

            )


            duration_ms = self._duration_ms(

                started

            )


            if response.status_code in (401, 403):

                return HikvisionRecordingTracksResult(

                    supported=True,

                    resolved=False,

                    tracks=[],

                    enabled_tracks=0,

                    recording_tracks=0,

                    message=(

                        "Falha de autenticação "

                        "na ISAPI Hikvision"

                    ),

                    status_code=response.status_code,

                    duration_ms=duration_ms,

                )


            if response.status_code == 404:

                return HikvisionRecordingTracksResult(

                    supported=False,

                    resolved=False,

                    tracks=[],

                    enabled_tracks=0,

                    recording_tracks=0,

                    message=(

                        "Consulta de tracks "

                        "não suportada"

                    ),

                    status_code=404,

                    duration_ms=duration_ms,

                )


            response.raise_for_status()


            root = ET.fromstring(

                response.content

            )


            tracks: list[

                HikvisionRecordingTrack

            ] = []


            for element in root.iter():

                if (

                    self._local_name(element.tag)

                    != "Track"

                ):

                    continue


                track_id = self._to_int(

                    self._find_direct_text(

                        element,

                        "id",

                    )

                )


                channel_id = self._to_int(

                    self._find_direct_text(

                        element,

                        "Channel",

                    )

                )


                enabled = self._to_bool(

                    self._find_direct_text(

                        element,

                        "Enable",

                    )

                )


                description = (

                    self._find_direct_text(

                        element,

                        "Description",

                    )

                )


                recording_mode = (

                    self._find_direct_text(

                        element,

                        "DefaultRecordingMode",

                    )

                )


                source_descriptor = (

                    self._find_direct_child(

                        element,

                        "SrcDescriptor",

                    )

                )


                source_channel = None

                source_url = None


                if source_descriptor is not None:

                    source_channel = self._to_int(

                        self._find_text(

                            source_descriptor,

                            "SrcChannel",

                        )

                    )


                    source_url = self._find_text(

                        source_descriptor,

                        "SrcUrl",

                    )


                schedule_enabled = False

                record_enabled = False


                track_schedule = (

                    self._find_direct_child(

                        element,

                        "TrackSchedule",

                    )

                )


                if track_schedule is not None:

                    record_enabled = (

                        self._contains_true_value(

                            track_schedule,

                            "Record",

                        )

                    )


                custom_extension_list = (

                    self._find_direct_child(

                        element,

                        "CustomExtensionList",

                    )

                )


                if (

                    custom_extension_list

                    is not None

                ):

                    schedule_enabled = (

                        self._contains_true_value(

                            custom_extension_list,

                            "enableSchedule",

                        )

                    )


                track = HikvisionRecordingTrack(

                    track_id=track_id,

                    channel_id=channel_id,

                    source_channel=source_channel,

                    enabled=enabled,

                    schedule_enabled=(

                        schedule_enabled

                    ),

                    record_enabled=(

                        record_enabled

                    ),

                    recording_mode=(

                        recording_mode

                    ),

                    description=description,

                    source_url=source_url,

                )


                tracks.append(track)


            enabled_tracks = sum(

                1

                for track in tracks

                if track.enabled

            )


            recording_tracks = sum(

                1

                for track in tracks

                if (

                    track.enabled

                    and track.record_enabled

                )

            )


            if tracks:

                message = (

                    "Tracks de gravação "

                    "identificados"

                )

            else:

                message = (

                    "Nenhum track de gravação "

                    "identificado"

                )


            return HikvisionRecordingTracksResult(

                supported=True,

                resolved=True,

                tracks=tracks,

                enabled_tracks=enabled_tracks,

                recording_tracks=(

                    recording_tracks

                ),

                message=message,

                status_code=response.status_code,

                duration_ms=duration_ms,

            )


        except requests.RequestException as error:

            return HikvisionRecordingTracksResult(

                supported=False,

                resolved=False,

                tracks=[],

                enabled_tracks=0,

                recording_tracks=0,

                message=(

                    "Erro ao consultar tracks: "

                    f"{error}"

                ),

                status_code=None,

                duration_ms=self._duration_ms(

                    started

                ),

            )


        except ET.ParseError:

            return HikvisionRecordingTracksResult(

                supported=True,

                resolved=False,

                tracks=[],

                enabled_tracks=0,

                recording_tracks=0,

                message=(

                    "Resposta ISAPI de tracks "

                    "inválida"

                ),

                status_code=None,

                duration_ms=self._duration_ms(

                    started

                ),

            )


    # ========================================================

    # PESQUISA DE GRAVAÇÕES

    # ========================================================


    def search_recordings(

        self,

        ip_address: str,

        username: str,

        password: str,

        track_id: int,

        start_time: str,

        end_time: str,

        port: int = 80,

        use_https: bool = False,

        max_results: int = 40,

        position: int = 0,

    ) -> HikvisionRecordingResult:

        started = time.perf_counter()


        scheme = "https" if use_https else "http"


        host = self._build_host(

            ip_address=ip_address,

            port=port,

            use_https=use_https,

        )


        url = (

            f"{scheme}://{host}"

            "/ISAPI/ContentMgmt/search"

        )


        search_id = str(uuid.uuid4())


        xml_body = f"""<?xml version="1.0" encoding="UTF-8"?>

<CMSearchDescription>

    <searchID>{search_id}</searchID>

    <trackIDList>

        <trackID>{track_id}</trackID>

    </trackIDList>

    <timeSpanList>

        <timeSpan>

            <startTime>{start_time}</startTime>

            <endTime>{end_time}</endTime>

        </timeSpan>

    </timeSpanList>

    <contentTypeList>

        <contentType>video</contentType>

    </contentTypeList>

    <maxResults>{max_results}</maxResults>

    <searchResultPostion>{position}</searchResultPostion>

</CMSearchDescription>

"""


        try:

            response = requests.post(

                url,

                auth=HTTPDigestAuth(

                    username,

                    password,

                ),

                data=xml_body.encode(

                    "utf-8"

                ),

                headers={

                    "Content-Type":

                        "application/xml",

                },

                timeout=self.timeout_seconds,

                verify=False,

            )


            duration_ms = self._duration_ms(

                started

            )


            if response.status_code in (401, 403):

                return HikvisionRecordingResult(

                    supported=True,

                    resolved=False,

                    recording_found=False,

                    track_id=track_id,

                    num_of_matches=0,

                    has_more=False,

                    first_recording=None,

                    latest_recording=None,

                    segments=[],

                    message=(

                        "Falha de autenticação "

                        "na ISAPI Hikvision"

                    ),

                    status_code=response.status_code,

                    duration_ms=duration_ms,

                )


            if response.status_code == 404:

                return HikvisionRecordingResult(

                    supported=False,

                    resolved=False,

                    recording_found=False,

                    track_id=track_id,

                    num_of_matches=0,

                    has_more=False,

                    first_recording=None,

                    latest_recording=None,

                    segments=[],

                    message=(

                        "Pesquisa de gravações "

                        "não suportada"

                    ),

                    status_code=404,

                    duration_ms=duration_ms,

                )


            response.raise_for_status()


            root = ET.fromstring(

                response.content

            )


            response_status = self._find_text(

                root,

                "responseStatus",

            )


            response_status_string = (

                self._find_text(

                    root,

                    "responseStatusStrg",

                )

            )


            num_of_matches = (

                self._to_int(

                    self._find_text(

                        root,

                        "numOfMatches",

                    )

                )

                or 0

            )


            resolved = (

                (response_status or "")

                .strip()

                .lower()

                == "true"

            )


            has_more = (

                (response_status_string or "")

                .strip()

                .upper()

                == "MORE"

            )


            segments: list[

                HikvisionRecordingSegment

            ] = []


            for element in root.iter():

                if (

                    self._local_name(element.tag)

                    != "searchMatchItem"

                ):

                    continue


                segment = (

                    HikvisionRecordingSegment(

                        track_id=self._to_int(

                            self._find_text(

                                element,

                                "trackID",

                            )

                        ),

                        start_time=self._find_text(

                            element,

                            "startTime",

                        ),

                        end_time=self._find_text(

                            element,

                            "endTime",

                        ),

                        content_type=(

                            self._find_text(

                                element,

                                "contentType",

                            )

                        ),

                        codec_type=(

                            self._find_text(

                                element,

                                "codecType",

                            )

                        ),

                        recording_type=(

                            self._find_text(

                                element,

                                "metadataDescriptor",

                            )

                        ),

                    )

                )


                segments.append(segment)


            recording_found = bool(

                segments

            )


            first_recording = (

                segments[0].start_time

                if segments

                else None

            )


            latest_recording = (

                segments[-1].end_time

                if segments

                else None

            )


            if recording_found:

                message = (

                    "Gravações encontradas"

                )

            elif resolved:

                message = (

                    "Nenhuma gravação encontrada "

                    "no período consultado"

                )

            else:

                message = (

                    response_status_string

                    or

                    "Pesquisa de gravações "

                    "não resolvida"

                )


            return HikvisionRecordingResult(

                supported=True,

                resolved=resolved,

                recording_found=(

                    recording_found

                ),

                track_id=track_id,

                num_of_matches=(

                    num_of_matches

                ),

                has_more=has_more,

                first_recording=(

                    first_recording

                ),

                latest_recording=(

                    latest_recording

                ),

                segments=segments,

                message=message,

                status_code=response.status_code,

                duration_ms=duration_ms,

            )


        except requests.RequestException as error:

            return HikvisionRecordingResult(

                supported=False,

                resolved=False,

                recording_found=False,

                track_id=track_id,

                num_of_matches=0,

                has_more=False,

                first_recording=None,

                latest_recording=None,

                segments=[],

                message=(

                    "Erro ao pesquisar gravações: "

                    f"{error}"

                ),

                status_code=None,

                duration_ms=self._duration_ms(

                    started

                ),

            )


        except ET.ParseError:

            return HikvisionRecordingResult(

                supported=True,

                resolved=False,

                recording_found=False,

                track_id=track_id,

                num_of_matches=0,

                has_more=False,

                first_recording=None,

                latest_recording=None,

                segments=[],

                message=(

                    "Resposta ISAPI de gravações "

                    "inválida"

                ),

                status_code=None,

                duration_ms=self._duration_ms(

                    started

                ),

            )


    # ========================================================

    # DIAGNÓSTICO DE GRAVAÇÃO

    # ========================================================


    def get_recording_diagnostics(

        self,

        ip_address: str,

        username: str,

        password: str,

        track_id: int = 101,

        port: int = 80,

        use_https: bool = False,

    ) -> HikvisionRecordingDiagnostics:

        started = time.perf_counter()


        # Neste DVR os horários retornados pela ISAPI

        # acompanham o relógio operacional do equipamento,

        # apesar do sufixo "Z".

        #

        # Por enquanto preservamos essa semântica e não

        # fazemos conversão automática de timezone.


        now = datetime.now()


        historical_start = (

            now - timedelta(days=365)

        )


        historical_result = (

            self.search_recordings(

                ip_address=ip_address,

                username=username,

                password=password,

                track_id=track_id,

                start_time=(

                    historical_start.strftime(

                        "%Y-%m-%dT00:00:00Z"

                    )

                ),

                end_time=now.strftime(

                    "%Y-%m-%dT23:59:59Z"

                ),

                port=port,

                use_https=use_https,

                max_results=40,

                position=0,

            )

        )


        if not historical_result.resolved:

            return (

                HikvisionRecordingDiagnostics(

                    supported=(

                        historical_result.supported

                    ),

                    resolved=False,

                    recording_found=False,

                    track_id=track_id,

                    first_recording=None,

                    latest_recording=None,

                    history_days=None,

                    recent_recording_found=False,

                    message=(

                        historical_result.message

                    ),

                    duration_ms=(

                        self._duration_ms(

                            started

                        )

                    ),

                )

            )


        first_recording = (

            historical_result.first_recording

        )


        recent_start = (

            now - timedelta(days=1)

        )


        recent_result = (

            self.search_recordings(

                ip_address=ip_address,

                username=username,

                password=password,

                track_id=track_id,

                start_time=(

                    recent_start.strftime(

                        "%Y-%m-%dT%H:%M:%SZ"

                    )

                ),

                end_time=now.strftime(

                    "%Y-%m-%dT23:59:59Z"

                ),

                port=port,

                use_https=use_https,

                max_results=40,

                position=0,

            )

        )


        latest_recording = (

            recent_result.latest_recording

            if recent_result.resolved

            else None

        )


        recording_found = (

            historical_result.recording_found

            or recent_result.recording_found

        )


        history_days = (

            self._calculate_history_days(

                first_recording=(

                    first_recording

                ),

                latest_recording=(

                    latest_recording

                ),

            )

        )


        if recording_found:

            message = (

                "Histórico de gravação "

                "identificado"

            )

        else:

            message = (

                "Nenhuma gravação "

                "identificada"

            )


        return HikvisionRecordingDiagnostics(

            supported=True,

            resolved=True,

            recording_found=recording_found,

            track_id=track_id,

            first_recording=first_recording,

            latest_recording=latest_recording,

            history_days=history_days,

            recent_recording_found=(

                recent_result.recording_found

            ),

            message=message,

            duration_ms=self._duration_ms(

                started

            ),

        )


    # ========================================================
    # RELÓGIO DO EQUIPAMENTO
    # ========================================================

    @staticmethod
    def _classify_recording_delay(
        *, resolved: bool, recording_found: bool, has_more: bool,
        age_seconds: float | None, threshold_seconds: float,
        confirmation_checks: int, previous_count: int,
    ) -> tuple[str, int]:
        """Classifica consultas completas; dados inconclusivos zeram a sequencia."""
        if not resolved or has_more:
            return "unknown", 0
        if not recording_found:
            return "no_recording", 0
        if age_seconds is None or not (0 <= age_seconds < float("inf")):
            return "unknown", 0
        if age_seconds <= threshold_seconds:
            return "within_tolerance", 0
        count = min(previous_count + 1, confirmation_checks)
        if count >= confirmation_checks:
            return "delayed", count
        return "pending_delay", count

    @staticmethod
    def _parse_device_local_time(local_time: str | None) -> datetime | None:
        """Interpreta o horario do DVR preservando seu relogio local."""
        if not isinstance(local_time, str) or not local_time.strip():
            return None

        value = local_time.strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        try:
            return datetime.fromisoformat(value).replace(tzinfo=None)
        except ValueError:
            return None

    def get_device_time(
        self,
        ip_address: str,
        username: str,
        password: str,
        port: int = 80,
        use_https: bool = False,
    ) -> HikvisionDeviceTimeResult:
        started = time.perf_counter()

        scheme = "https" if use_https else "http"
        host = self._build_host(
            ip_address=ip_address,
            port=port,
            use_https=use_https,
        )

        url = f"{scheme}://{host}/ISAPI/System/time"

        try:
            response = requests.get(
                url,
                auth=HTTPDigestAuth(
                    username,
                    password,
                ),
                timeout=self.timeout_seconds,
                verify=False,
            )

            duration_ms = self._duration_ms(started)

            if response.status_code in (401, 403):
                return HikvisionDeviceTimeResult(
                    supported=True,
                    resolved=False,
                    time_mode=None,
                    local_time=None,
                    timezone=None,
                    message=(
                        "Falha de autenticação "
                        "na ISAPI Hikvision"
                    ),
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                )

            if response.status_code == 404:
                return HikvisionDeviceTimeResult(
                    supported=False,
                    resolved=False,
                    time_mode=None,
                    local_time=None,
                    timezone=None,
                    message=(
                        "Consulta do relógio "
                        "não suportada"
                    ),
                    status_code=404,
                    duration_ms=duration_ms,
                )

            response.raise_for_status()
            root = ET.fromstring(response.content)

            local_time = self._find_text(
                root,
                "localTime",
            )

            return HikvisionDeviceTimeResult(
                supported=True,
                resolved=bool(local_time),
                time_mode=self._find_text(
                    root,
                    "timeMode",
                ),
                local_time=local_time,
                timezone=self._find_text(
                    root,
                    "timeZone",
                ),
                message=(
                    "Relógio do equipamento identificado"
                    if local_time
                    else "Horário local não identificado"
                ),
                status_code=response.status_code,
                duration_ms=duration_ms,
            )

        except requests.RequestException as error:
            return HikvisionDeviceTimeResult(
                supported=False,
                resolved=False,
                time_mode=None,
                local_time=None,
                timezone=None,
                message=(
                    "Erro ao consultar relógio: "
                    f"{error}"
                ),
                status_code=None,
                duration_ms=self._duration_ms(started),
            )

        except ET.ParseError:
            return HikvisionDeviceTimeResult(
                supported=True,
                resolved=False,
                time_mode=None,
                local_time=None,
                timezone=None,
                message=(
                    "Resposta ISAPI de horário inválida"
                ),
                status_code=None,
                duration_ms=self._duration_ms(started),
            )


    # ========================================================
    # DIAGNÓSTICO RECENTE POR CANAL
    # ========================================================

    def get_channels_recording_diagnostics(
        self,
        ip_address: str,
        username: str,
        password: str,
        port: int = 80,
        use_https: bool = False,
        recent_hours: int = 24,
        delay_threshold_seconds: float = 180.0,
        confirmation_checks: int = 2,
    ) -> HikvisionChannelsRecordingDiagnostics:
        started = time.perf_counter()

        if not (0 <= delay_threshold_seconds < float("inf")):
            raise ValueError("delay_threshold_seconds deve ser finito e >= 0")
        if (
            isinstance(confirmation_checks, bool)
            or not isinstance(confirmation_checks, int)
            or confirmation_checks < 1
        ):
            raise ValueError("confirmation_checks deve ser inteiro >= 1")

        device_key = (ip_address, port, use_https, username)
        policy = (delay_threshold_seconds, confirmation_checks, recent_hours)
        previous_policy, previous_counts = self._recording_delay_history.pop(
            device_key, (None, {})
        )
        if previous_policy != policy:
            previous_counts = {}
        current_counts = {}

        tracks_result = self.get_recording_tracks(
            ip_address=ip_address,
            username=username,
            password=password,
            port=port,
            use_https=use_https,
        )

        if not tracks_result.resolved:
            return HikvisionChannelsRecordingDiagnostics(
                supported=tracks_result.supported,
                resolved=False,
                configured_channels=0,
                channels_with_recent_recording=0,
                channels=[],
                message=tracks_result.message,
                duration_ms=self._duration_ms(started),
            )

        candidate_tracks = [
            track
            for track in tracks_result.tracks
            if (
                track.enabled
                and track.record_enabled
                and track.track_id is not None
                and track.source_channel is not None
            )
        ]

        # Um equipamento pode expor mais de um track por canal.
        # Para este diagnóstico usamos somente um track
        # habilitado/configurado de cada canal.
        tracks_by_channel: dict[
            int,
            HikvisionRecordingTrack,
        ] = {}

        for track in candidate_tracks:
            if track.source_channel is None:
                continue

            if track.source_channel not in tracks_by_channel:
                tracks_by_channel[
                    track.source_channel
                ] = track

        device_time_result = self.get_device_time(
            ip_address=ip_address,
            username=username,
            password=password,
            port=port,
            use_https=use_https,
        )

        now = datetime.now()
        device_now = None

        if (
            device_time_result.resolved
            and device_time_result.local_time
        ):
            device_now = self._parse_device_local_time(
                device_time_result.local_time
            )

            if device_now is not None:
                now = device_now

        recent_start = now - timedelta(
            hours=max(1, recent_hours)
        )

        # Neste firmware, os timestamps da pesquisa de gravação
        # usam o mesmo relógio operacional/local do DVR, apesar
        # do sufixo "Z". Portanto preservamos os valores de
        # relógio e não aplicamos conversão automática para UTC.
        start_time = recent_start.strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        end_time = now.strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        channels: list[
            HikvisionChannelRecordingDiagnostic
        ] = []

        for channel_number in sorted(
            tracks_by_channel
        ):
            track = tracks_by_channel[
                channel_number
            ]

            channel_started = time.perf_counter()

            result = self.search_recordings(
                ip_address=ip_address,
                username=username,
                password=password,
                track_id=track.track_id,
                start_time=start_time,
                end_time=end_time,
                port=port,
                use_https=use_https,
                max_results=40,
                position=0,
            )

            recording_age_seconds = None
            if (
                device_now is not None
                and result.resolved
                and result.recording_found
            ):
                latest_local = self._parse_device_local_time(
                    result.latest_recording
                )
                if latest_local is not None:
                    # Mesmo relogio local usado na janela de pesquisa.
                    # Valores negativos ficam visiveis para diagnostico.
                    recording_age_seconds = (
                        device_now - latest_local
                    ).total_seconds()

            recording_status, delayed_count = self._classify_recording_delay(
                resolved=result.resolved,
                recording_found=result.recording_found,
                has_more=result.has_more,
                age_seconds=recording_age_seconds,
                threshold_seconds=delay_threshold_seconds,
                confirmation_checks=confirmation_checks,
                previous_count=previous_counts.get(track.track_id, 0),
            )
            current_counts[track.track_id] = delayed_count

            channels.append(
                HikvisionChannelRecordingDiagnostic(
                    channel=track.source_channel,
                    track_id=track.track_id,
                    configured=True,
                    enabled=track.enabled,
                    schedule_enabled=(
                        track.schedule_enabled
                    ),
                    record_enabled=(
                        track.record_enabled
                    ),
                    resolved=result.resolved,
                    recording_found=(
                        result.recording_found
                    ),
                    latest_recording=(
                        result.latest_recording
                    ),
                    num_of_matches=(
                        result.num_of_matches
                    ),
                    has_more=result.has_more,
                    recording_age_seconds=recording_age_seconds,
                    recording_status=recording_status,
                    consecutive_delayed_checks=delayed_count,
                    message=result.message,
                    duration_ms=self._duration_ms(
                        channel_started
                    ),
                )
            )

        self._recording_delay_history[device_key] = (policy, current_counts)
        configured_channels = len(channels)

        channels_with_recent_recording = sum(
            1
            for channel in channels
            if (
                channel.resolved
                and channel.recording_found
            )
        )

        all_resolved = (
            bool(channels)
            and all(
                channel.resolved
                for channel in channels
            )
        )

        if not channels:
            message = (
                "Nenhum canal habilitado e configurado "
                "para gravação foi identificado"
            )
        elif all_resolved:
            message = (
                "Diagnóstico recente dos canais concluído"
            )
        else:
            message = (
                "Diagnóstico recente concluído "
                "com consultas não resolvidas"
            )

        return HikvisionChannelsRecordingDiagnostics(
            supported=True,
            resolved=all_resolved,
            device_local_time=(
                device_time_result.local_time
                if device_now is not None else None
            ),
            configured_channels=configured_channels,
            channels_with_recent_recording=(
                channels_with_recent_recording
            ),
            channels=channels,
            message=message,
            duration_ms=self._duration_ms(started),
        )


    # ========================================================

    # HELPERS

    # ========================================================


    @staticmethod

    def _build_host(

        ip_address: str,

        port: int,

        use_https: bool,

    ) -> str:

        default_port = (

            443

            if use_https

            else 80

        )


        if port == default_port:

            return ip_address


        return f"{ip_address}:{port}"


    @staticmethod

    def _duration_ms(

        started: float,

    ) -> int:

        return int(

            (

                time.perf_counter()

                - started

            )

            * 1000

        )


    @staticmethod

    def _local_name(

        tag: str,

    ) -> str:

        if "}" in tag:

            return tag.split(

                "}",

                1,

            )[1]


        return tag


    def _find_text(

        self,

        element: ET.Element,

        name: str,

    ) -> str | None:

        for child in element.iter():

            if (

                self._local_name(child.tag)

                != name

            ):

                continue


            if child.text is None:

                return None


            value = child.text.strip()


            return value or None


        return None


    def _find_direct_text(

        self,

        element: ET.Element,

        name: str,

    ) -> str | None:

        for child in list(element):

            if (

                self._local_name(child.tag)

                != name

            ):

                continue


            if child.text is None:

                return None


            value = child.text.strip()


            return value or None


        return None


    def _find_direct_child(

        self,

        element: ET.Element,

        name: str,

    ) -> ET.Element | None:

        for child in list(element):

            if (

                self._local_name(child.tag)

                == name

            ):

                return child


        return None


    def _contains_true_value(

        self,

        element: ET.Element,

        name: str,

    ) -> bool:

        for child in element.iter():

            if (

                self._local_name(child.tag)

                != name

            ):

                continue


            if self._to_bool(child.text):

                return True


        return False


    @staticmethod

    def _to_bool(

        value: str | None,

    ) -> bool:

        if value is None:

            return False


        return (

            value.strip().lower()

            in {

                "true",

                "1",

                "yes",

                "on",

            }

        )


    @staticmethod

    def _to_int(

        value: str | None,

    ) -> int | None:

        if value is None:

            return None


        try:

            return int(value)

        except ValueError:

            return None


    @staticmethod

    def _disk_is_healthy(

        disk: HikvisionDisk,

    ) -> bool:

        status = (

            disk.status or ""

        ).strip().lower()


        property_value = (

            disk.property or ""

        ).strip().upper()


        status_ok = (

            status == "ok"

        )


        writable = (

            property_value == "RW"

        )


        # free_space_mb NÃO participa do cálculo.

        #

        # Em DVR/NVR trabalhando com sobrescrita ou

        # alocação completa, freeSpace=0 pode ser normal.


        return (

            status_ok

            and writable

        )


    @staticmethod

    def _calculate_history_days(

        first_recording: str | None,

        latest_recording: str | None,

    ) -> float | None:

        if (

            not first_recording

            or not latest_recording

        ):

            return None


        try:

            first_dt = datetime.strptime(

                first_recording,

                "%Y-%m-%dT%H:%M:%SZ",

            )


            latest_dt = datetime.strptime(

                latest_recording,

                "%Y-%m-%dT%H:%M:%SZ",

            )


            seconds = (

                latest_dt - first_dt

            ).total_seconds()


            if seconds < 0:

                return None


            return round(

                seconds / 86400,

                2,

            )


        except ValueError:

            return None