"""One diagnostic run, including short delay confirmation within the same job."""
import time
from app.hikvision_scanner import HikvisionScanner


def collect_recordings(ip_address, username, password, port=80, *,
                       scanner_factory=HikvisionScanner, sleep=time.sleep):
    # Fresh instance: yesterday's or another manual job's evidence cannot confirm today.
    scanner = scanner_factory()
    started = time.perf_counter()
    result = scanner.get_channels_recording_diagnostics(
        ip_address=ip_address, username=username, password=password, port=port,
        delay_threshold_seconds=180, confirmation_checks=2,
    )
    initial_pending = {c.channel for c in result.channels if c.recording_status == "pending_delay"}
    queries = 1
    if initial_pending:
        sleep(20)
        result = scanner.get_channels_recording_diagnostics(
            ip_address=ip_address, username=username, password=password, port=port,
            delay_threshold_seconds=180, confirmation_checks=2,
        )
        queries = 2
    data = result.to_dict()
    data.update(delay_threshold_seconds=180, confirmation_checks=2,
                confirmation_interval_seconds=20, queries_performed=queries,
                duration_ms=int((time.perf_counter() - started) * 1000))
    # Channels which only become delayed on the second pass remain pending.
    data["confirmation_completed"] = not any(
        c.recording_status == "pending_delay" for c in result.channels
    ) and result.resolved and initial_pending.issubset({
        c.channel for c in result.channels if c.recording_status in ("delayed", "within_tolerance")
    })
    return data
