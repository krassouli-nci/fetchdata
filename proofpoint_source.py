import os
import requests
import time
import logging
from datetime import datetime, timezone

class ProofpointSource:
    def __init__(self, config):
        self.config = config
        self.api_base = config["PROOFPOINT_API_BASE"].rstrip("/")
        self.access_token = config["PROOFPOINT_ACCESS_TOKEN"]
        self.refresh_token = config["PROOFPOINT_REFRESH_TOKEN"]
        self.token_expiry = 0  # Optional: store expiry time if available

    def refresh_access_token(self):
        url = f"{self.api_base}/oauth2/token"
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token
        }
        logging.info("Refreshing Proofpoint access token using refresh token...")
        r = requests.post(
            url,
            data=data,
            timeout=30,
            verify=self.config["PROOFPOINT_CA_CERT"]  # <--- HERE!
        )
        r.raise_for_status()
        tokens = r.json()
        self.access_token = tokens["access_token"]
        if "refresh_token" in tokens:
            self.refresh_token = tokens["refresh_token"]
        self.token_expiry = time.time() + int(tokens.get("expires_in", 3599)) - 60
        logging.info("Successfully refreshed Proofpoint access token.")
        return self.access_token


    def get_token(self):
        # Optionally: implement expiry logic if token_expiry is tracked
        if self.token_expiry and time.time() < self.token_expiry:
            return self.access_token
        return self.refresh_access_token()

    def fetch_events(self):
        """
        Generator that yields (events, to_time).
        Modify endpoint/params as needed for your use-case.
        """
        endpoint = f"{self.api_base}/v2/alerts"
        params = {
            "start_time": self.config.get("PROOFPOINT_START_TIME"),  # e.g., "2024-06-01T00:00:00Z"
            "end_time": self.config.get("PROOFPOINT_END_TIME"),
            "limit": self.config.get("PROOFPOINT_LIMIT", 500)
        }
        next_page = None
        while True:
            if next_page:
                params["page_token"] = next_page
            headers = {"Authorization": f"Bearer {self.get_token()}"}
            response = requests.get(endpoint, headers=headers, params=params, timeout=60, verify=self.config["PROOFPOINT_CA_CERT"] )
            if response.status_code == 401:
                # Unauthorized: likely expired, refresh and retry
                logging.warning("Access token expired; refreshing and retrying...")
                self.refresh_access_token()
                headers = {"Authorization": f"Bearer {self.access_token}"}
                response = requests.get(endpoint, headers=headers, params=params, timeout=60,verify=self.config["PROOFPOINT_CA_CERT"] )
            response.raise_for_status()
            data = response.json()
            events = data.get("alerts", [])
            yield events, int(datetime.now(timezone.utc).timestamp())
            next_page = data.get("next_page_token")
            if not next_page:
                break

    def compute_unique_id(self, event):
        import hashlib, json
        raw = f"{event.get('id')}-{event.get('created_at')}-{event.get('type')}"
        return "Proofpoint_" + hashlib.sha256(raw.encode()).hexdigest()[:64]
