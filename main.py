from proofpoint_source import ProofpointSource
from dotenv import load_dotenv
import os

def load_config():
    import os
    from pathlib import Path
    from dotenv import load_dotenv

    # Always load .env from the script's directory
    BASE_DIR = Path(__file__).parent.resolve()
    load_dotenv(dotenv_path=BASE_DIR / ".env", override=True)

    # Resolve CA cert absolute path if set
    ca_cert_rel = os.getenv("PROOFPOINT_CA_CERT", "cert/corp-root-ca.crt")
    ca_cert_abs = str(BASE_DIR / ca_cert_rel)

    config = {
        "PROOFPOINT_API_BASE": os.environ["PROOFPOINT_API_BASE"],
        "PROOFPOINT_ACCESS_TOKEN": os.environ["PROOFPOINT_ACCESS_TOKEN"],
        "PROOFPOINT_REFRESH_TOKEN": os.environ["PROOFPOINT_REFRESH_TOKEN"],
        "PROOFPOINT_START_TIME": os.getenv("PROOFPOINT_START_TIME"),
        "PROOFPOINT_END_TIME": os.getenv("PROOFPOINT_END_TIME"),
        "PROOFPOINT_LIMIT": int(os.getenv("PROOFPOINT_LIMIT", 500)),
        "PROOFPOINT_CA_CERT": ca_cert_abs,
        # Add your SQL config here as needed
    }
    return config

if __name__ == "__main__":
    config = load_config()
    source = ProofpointSource(config)
    for events, to_time in source.fetch_events():
        print(f"Fetched {len(events)} events. to_time={to_time}")
        # Do your processing here
