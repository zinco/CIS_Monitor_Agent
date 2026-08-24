import requests


class ApiClient:
    def __init__(self, base_url: str, token: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })

    def get_config(self) -> dict:
        response = self.session.get(
            f"{self.base_url}/monitoring/config",
            timeout=self.timeout,
        )

        response.raise_for_status()

        return response.json()

    def get_devices(self) -> list:
        response = self.session.get(
            f"{self.base_url}/monitoring/devices",
            timeout=self.timeout,
        )

        response.raise_for_status()

        return response.json().get("data", [])

    def send_heartbeat(
        self,
        hostname: str,
        version: str,
    ) -> dict:
        response = self.session.post(
            f"{self.base_url}/monitoring/heartbeat",
            json={
                "hostname": hostname,
                "version": version,
            },
            timeout=self.timeout,
        )

        response.raise_for_status()

        return response.json()

    def send_result(self, data: dict) -> dict:
        response = self.session.post(
            f"{self.base_url}/monitoring/results",
            json=data,
            timeout=self.timeout,
        )

        response.raise_for_status()

        return response.json()