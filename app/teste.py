from app.hikvision_scanner import HikvisionScanner

scanner = HikvisionScanner()

result = scanner.search_recordings(
    ip_address="192.168.130.250",
    username="admin",
    password="admin7761",
    track_id=101,
    start_time="2026-09-17T00:00:00Z",
    end_time="2026-09-17T23:59:59Z",
)

print(result.to_dict())