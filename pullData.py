import os
import sys
import json
import urllib.parse
import base64
import logging
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

import requests
import pyodbc
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

    config["SQL_SERVER"] = os.getenv("SQL_SERVER")
    config["SQL_DATABASE"] = os.getenv("SQL_DATABASE")
    config["SQL_USERNAME"] = os.getenv("SQL_USERNAME")
    config["SQL_PASSWORD"] = os.getenv("SQL_PASSWORD")
    config["SQL_DRIVER"] = os.getenv("SQL_DRIVER", "ODBC Driver 17 for SQL Server")
    config["SQL_TABLE"] = os.getenv("SQL_TABLE", "akamai_events")
    config["OUTPUT_MODE"] = os.getenv("OUTPUT_MODE", "sql")

    return config

def create_session(client_token, client_secret, access_token):
    session = requests.Session()
    session.auth = EdgeGridAuth(
        client_token=client_token,
        client_secret=client_secret,
        access_token=access_token,
    )
    return session

def fetch_events(session, host, config_id):
    url = f"https://{host}/siem/v1/configs/{config_id}"
    limit = 20000
    events = []
    to_file = Path(".akamai_to")

    now = int(datetime.now(timezone.utc).timestamp())
    prev_to = int(to_file.read_text().strip()) if to_file.exists() else now - 1000
    from_time = prev_to
    to_time = now - 5

    logging.info(f"Fetching events from {from_time} to {to_time}")
    params = {"from": from_time, "to": to_time, "limit": limit}

    batch_number = 1

    while True:
        response = session.get(url, params=params, timeout=60)
        if response.status_code != 200:
            logging.error(f"Error {response.status_code}: {response.text}")
            break

        lines = response.text.strip().splitlines()
        if not lines:
            logging.info("No data returned.")
            break

        num_events = len(lines) - 1
        logging.info(f"Batch {batch_number}: Retrieved {num_events} events")
        batch_number += 1

        if num_events == 0:
            break

        for line in lines[:-1]:
            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError:
                continue

        try:
            offset_context = json.loads(lines[-1])
            if offset_context.get("total", 1) == 0:
                break
            next_offset = offset_context.get("offset")
            if not next_offset:
                break
            params = {"offset": next_offset, "limit": limit}
        except json.JSONDecodeError:
            logging.error("Failed to parse offset context. Stopping.")
            break

    to_file.write_text(str(to_time+1))
    return events

def decode_and_split(value_string):
    seen = set()
    decoded_values = []
    try:
        decoded = urllib.parse.unquote(value_string)
        for val in decoded.split(";"):
            val = val.strip()
            if not val or val in seen:
                continue
            seen.add(val)
            try:
                val = base64.b64decode(val.encode("utf-8"), validate=True).decode("utf-8").strip()
            except Exception:
                pass
            decoded_values.append(val)
    except Exception as e:
        logging.warning(f"Decode error: {e}")
    return decoded_values

def batch_insert(cursor, sql, data, batch_size=10000, table_name=""):
    for i in range(0, len(data), batch_size):
        chunk = data[i:i+batch_size]
        try:
            cursor.executemany(sql, chunk)
            cursor.connection.commit()
        except pyodbc.IntegrityError as e:
            if "duplicate key" in str(e).lower() or "primary key" in str(e).lower():
                logging.error(f"Duplicate key error during insert into {table_name}: {e}")
                # Fallback: insert rows one by one
                for row in chunk:
                    try:
                        cursor.execute(sql, row)
                        cursor.connection.commit()
                    except pyodbc.IntegrityError as single_e:
                        if "duplicate key" in str(single_e).lower() or "primary key" in str(single_e).lower():
                            logging.warning(f"Skipped duplicate key in {table_name}: {row[0]}")
                        else:
                            logging.exception(f"Database error during per-row insert into {table_name}:")
            else:
                logging.exception(f"Database error during insert into {table_name}:")
                continue
        label = f" for table '{table_name}'" if table_name else ""
        logging.info(f"Committed batch {i + len(chunk)} / {len(data)}{label}")

def write_to_mssql(config, events):
    conn_str = (
        f"DRIVER={{{config['SQL_DRIVER']}}};"
        f"SERVER={config['SQL_SERVER']};"
        f"DATABASE={config['SQL_DATABASE']};"
        f"UID={config['SQL_USERNAME']};"
        f"PWD={config['SQL_PASSWORD']};"
        f"TrustServerCertificate=yes;Encrypt=yes;"
    )

    conn = pyodbc.connect(conn_str)
    if hasattr(conn, "fast_executemany"):
        conn.fast_executemany = True

    cursor = conn.cursor()

    total = len(events)
    main_rows = []
    child_tables = {
        "akamai_attack_ruleActions": [],
        "akamai_attack_ruleData": [],
        "akamai_attack_ruleMessages": [],
        "akamai_attack_ruleSelectors": [],
        "akamai_attack_ruleTags": [],
        "akamai_attack_ruleVersions": [],
        "akamai_attack_rules": [],
    }

    child_columns = {
        "akamai_attack_ruleActions": "rule_action",
        "akamai_attack_ruleData": "rule_data",
        "akamai_attack_ruleMessages": "rule_message",
        "akamai_attack_ruleSelectors": "rule_selector",
        "akamai_attack_ruleTags": "rule_tag",
        "akamai_attack_ruleVersions": "rule_version",
        "akamai_attack_rules": "rule_id",
    }

    seen_request_ids = set()
    for idx, event in enumerate(events, 1):
        ad = event.get("attackData", {})
        bot = event.get("botData", {})
        cd = event.get("clientData", {})
        geo = event.get("geo", {})
        http = event.get("httpMessage", {})
        urd = event.get("userRiskData", {})
        request_id = http.get("requestId")

        if not request_id or request_id in seen_request_ids:
            continue
        seen_request_ids.add(request_id)

        main_rows.append((
            request_id, event.get("format"), event.get("type"), event.get("version"), event.get("responseSegment"),
            ad.get("apiId"), ad.get("apiKey"), ad.get("clientIP"),
            ad.get("clientReputation"), ad.get("configId"), ad.get("policyId"),
            ad.get("slowPostAction"), ad.get("slowPostRate"), ad.get("custom"),
            bot.get("botScore"),
            cd.get("appBundleId"), cd.get("appVersion"), cd.get("sdkVersion"), cd.get("telemetryType"),
            geo.get("asn"), geo.get("city"), geo.get("continent"), geo.get("country"), geo.get("regionCode"),
            http.get("bytes"), http.get("host"), http.get("method"),
            http.get("path"), http.get("port"), http.get("protocol"),
            http.get("query"), http.get("start"), http.get("status"), http.get("tls"),
            urd.get("allow"), urd.get("general"), urd.get("originUserId"),
            urd.get("risk"), urd.get("score"), urd.get("status"),
            urd.get("trust"), urd.get("username"), urd.get("uuid")
        ))

        for table, column, val in [
            ("akamai_attack_ruleActions", "rule_action", ad.get("ruleActions")),
            ("akamai_attack_ruleData", "rule_data", ad.get("ruleData")),
            ("akamai_attack_ruleMessages", "rule_message", ad.get("ruleMessages")),
            ("akamai_attack_ruleSelectors", "rule_selector", ad.get("ruleSelectors")),
            ("akamai_attack_ruleTags", "rule_tag", ad.get("ruleTags")),
            ("akamai_attack_ruleVersions", "rule_version", ad.get("ruleVersions")),
            ("akamai_attack_rules", "rule_id", ad.get("rules")),
        ]:
            for v in decode_and_split(val):
                child_tables[table].append((request_id, v))

        if idx % 1000 == 0 or idx == total:
            percent = (idx / total) * 100
            logging.info(f"Progress: {idx}/{total} ({percent:.1f}%)")

    main_sql = f"""
        INSERT INTO {config['SQL_TABLE']} (
            requestId, format, type, version, responseSegment,
            attackData_apiId, attackData_apiKey, attackData_clientIP,
            attackData_clientReputation, attackData_configId, attackData_policyId,
            attackData_slowPostAction, attackData_slowPostRate, attackData_custom,
            botData_botScore,
            clientData_appBundleId, clientData_appVersion, clientData_sdkVersion, clientData_telemetryType,
            geo_asn, geo_city, geo_continent, geo_country, geo_regionCode,
            httpMessage_bytes, httpMessage_host, httpMessage_method,
            httpMessage_path, httpMessage_port, httpMessage_protocol,
            httpMessage_query, httpMessage_start, httpMessage_status, httpMessage_tls,
            userRiskData_allow, userRiskData_general, userRiskData_originUserId,
            userRiskData_risk, userRiskData_score, userRiskData_status,
            userRiskData_trust, userRiskData_username, userRiskData_uuid
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
    """
    batch_insert(cursor, main_sql, main_rows, table_name=config['SQL_TABLE'])

    for table, rows in child_tables.items():
        if rows:
            column = child_columns[table]
            sql = f"INSERT INTO {table} (requestId, {column}) VALUES (?, ?)"
            batch_insert(cursor, sql, rows, table_name=table)

    conn.commit()
    conn.close()
    logging.info(f"Inserted {total} events and child records into MSSQL.")

def group_events(events):
    seen_request_ids = set()
    by_hostname = defaultdict(int)
    by_category = defaultdict(int)
    by_path = defaultdict(int)
    by_method = defaultdict(int)
    by_tls_fingerprint = defaultdict(int)
    by_rule_action = defaultdict(int)

    for event in events:
        try:
            http = event.get("httpMessage", {})
            request_context = event.get("requestContext", {})
            attack_data = event.get("attackData", {})
            request_id = http.get("requestId")

            if not request_id or request_id in seen_request_ids:
                continue
            seen_request_ids.add(request_id)

            hostname = http.get("host", "unknown")
            path = http.get("path", "unknown")
            method = http.get("method", "unknown")
            tls_fingerprint = request_context.get("clientTlsFingerprint", "unknown")

            by_hostname[hostname] += 1
            by_path[path] += 1
            by_method[method] += 1
            by_tls_fingerprint[tls_fingerprint] += 1

            raw_actions = attack_data.get("ruleActions", "")
            if raw_actions:
                for action_decoded in decode_and_split(raw_actions):
                    if action_decoded:
                        by_rule_action[action_decoded] += 1

            raw_tags = attack_data.get("ruleTags", "")
            if raw_tags:
                for tag_decoded in decode_and_split(raw_tags):
                    if tag_decoded:
                        by_category[tag_decoded] += 1

        except Exception as e:
            logging.warning(f"Error processing event for grouping: {e}")
            continue

    return {
        "by_hostname": by_hostname,
        "by_category": by_category,
        "by_path": by_path,
        "by_method": by_method,
        "by_tls_fingerprint": by_tls_fingerprint,
        "by_rule_action": by_rule_action,
    }

def write_output(data, output_directory="output"):
    output_dir = Path(__file__).resolve().parent / output_directory
    output_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"akamai_output_{timestamp}.txt"

    with output_path.open("w", encoding='utf-8') as f:
        def write_section(title, counter):
            f.write(f"{title}:\n")
            for key, count in sorted(counter.items(), key=lambda x: (-x[1], x[0])):
                f.write(f"{key}: {count}\n")
            f.write("\n")

        write_section("Requests by Hostname", data["by_hostname"])
        write_section("Requests by Category (Rule Tags)", data["by_category"])
        write_section("Requests by Path", data["by_path"])
        write_section("Requests by Method", data["by_method"])
        write_section("Requests by TLS Fingerprint", data["by_tls_fingerprint"])
        write_section("Requests by Rule Action", data["by_rule_action"])

    logging.info(f"Output written to {output_path}")

def main():
    setup_logging()
    config = load_config()
    session = create_session(
        config["AKAMAI_CLIENT_TOKEN"],
        config["AKAMAI_CLIENT_SECRET"],
        config["AKAMAI_ACCESS_TOKEN"],
    )
    events = fetch_events(session, config["AKAMAI_HOST"], config["AKAMAI_SIEM_CONFIG_ID"])
    if not events:
        logging.info("No events retrieved.")
        return

    logging.info(f"Retrieved {len(events)} total events")

    if config["OUTPUT_MODE"].lower() == "sql":
        logging.info("Output mode: SQL. Writing data to MSSQL.")
        write_to_mssql(config, events)
    elif config["OUTPUT_MODE"].lower() == "txt":
        logging.info("Output mode: TXT. Grouping and writing data to text file.")
        grouped_data = group_events(events)
        write_output(grouped_data)
    else:
        logging.error(f"Invalid OUTPUT_MODE '{config['OUTPUT_MODE']}'. Must be 'sql' or 'txt'.")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
