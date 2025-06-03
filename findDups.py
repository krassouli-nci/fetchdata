import os
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
import requests
from akamai.edgegrid import EdgeGridAuth
from dotenv import load_dotenv

def setup_logging():
    log_dir = Path(__file__).resolve().parent / "logs"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "akamai_fetch.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, mode='a', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

def load_config():
    env_path = Path(__file__).resolve().parent / ".env"
    load_dotenv(dotenv_path=env_path, override=True)
    required_vars = [
        "AKAMAI_CLIENT_TOKEN", "AKAMAI_CLIENT_SECRET", "AKAMAI_ACCESS_TOKEN",
        "AKAMAI_HOST", "AKAMAI_SIEM_CONFIG_ID"
    ]
    config = {}
    for var in required_vars:
        config[var] = os.getenv(var)
        if not config[var]:
            raise EnvironmentError(f"Missing required .env value: {var}")
    config["BATCH_SIZE"] = int(os.getenv("BATCH_SIZE", "10000"))
    return config

def create_session(client_token, client_secret, access_token):
    session = requests.Session()
    session.auth = EdgeGridAuth(
        client_token=client_token,
        client_secret=client_secret,
        access_token=access_token,
    )
    return session

def fetch_events(session, host, config_id, limit=20000, from_time=None, to_time=None):
    url = f"https://{host}/siem/v1/configs/{config_id}"
    now = int(datetime.now(timezone.utc).timestamp())
    if from_time is None or to_time is None:
        from_time = now - 1000
        to_time = now - 5
    params = {"from": from_time, "to": to_time, "limit": limit}
    batch_number = 1
    while True:
        response = session.get(url, params=params, timeout=1800)
        if response.status_code != 200:
            logging.error(f"Error {response.status_code}: {response.text[:200]}...")
            break
        lines = response.text.strip().splitlines()
        if not lines:
            logging.info("No data returned.")
            break
        events = []
        num_events = len(lines) - 1
        logging.info(f"Batch {batch_number}: Retrieved {num_events} events")
        batch_number += 1
        if num_events == 0:
            break
        for line in lines[:-1]:
            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError as e:
                logging.warning(f"Skipping malformed JSON event line: {line[:200]}... Error: {e}")
                continue
        yield events
        try:
            offset_context = json.loads(lines[-1])
            if offset_context.get("total", 1) == 0:
                break
            next_offset = offset_context.get("offset")
            if not next_offset:
                break
            params = {"offset": next_offset, "limit": limit}
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse offset context (last line: {lines[-1][:200]}...). Stopping. Error: {e}")
            break

def compare_duplicates_print(events):
    """
    Finds all duplicate requestIds and prints their full JSON for comparison.
    """
    reqid_to_events = defaultdict(list)
    for event in events:
        req_id = None
        if isinstance(event, dict):
            # Typical Akamai SIEM has requestId inside httpMessage
            http_msg = event.get("httpMessage", {})
            req_id = http_msg.get("requestId")
        if req_id:
            reqid_to_events[req_id].append(event)
    # Print duplicates
    found_any = False
    for req_id, evlist in reqid_to_events.items():
        if len(evlist) > 1:
            found_any = True
            print(f"\n==== Duplicate requestId found: {req_id} (count: {len(evlist)}) ====")
            for i, ev in enumerate(evlist, 1):
                print(f"\n-- Event #{i} --")
                print(json.dumps(ev, indent=2))
    if not found_any:
        print("No duplicate requestId events found.")

def main():
    setup_logging()
    config = load_config()
    session = create_session(
        config["AKAMAI_CLIENT_TOKEN"],
        config["AKAMAI_CLIENT_SECRET"],
        config["AKAMAI_ACCESS_TOKEN"],
    )
    all_events = []
    total_events = 0
    # Optionally, let user set time window here
    # from_time = ...
    # to_time = ...
    from_time = "1747891764"
    to_time = "1748499422"
    for batch_events in fetch_events(session, config["AKAMAI_HOST"], config["AKAMAI_SIEM_CONFIG_ID"], limit=config["BATCH_SIZE"], from_time=from_time, to_time=to_time):
        if not batch_events:
            continue
        all_events.extend(batch_events)
        total_events += len(batch_events)
    print(f"Total events retrieved: {total_events}")
    compare_duplicates_print(all_events)

if __name__ == "__main__":
    main()
