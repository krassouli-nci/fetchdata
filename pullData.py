import os
import sys
import json
import urllib.parse
import base64
import logging
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
import time
from concurrent.futures import ThreadPoolExecutor

import requests
import pyodbc
pyodbc.pooling = True   # Enable ODBC connection pooling globally

from akamai.edgegrid import EdgeGridAuth
from dotenv import load_dotenv

FIELD_SIZE_LIMITS = {
    'requestId': 100,
    'format': 50,
    'type': 50,
    'version': 50,
    'responseSegment': 50,
    'attackData_apiId': 255,
    'attackData_apiKey': 255,
    'attackData_clientIP': 50,
    'attackData_clientReputation': 50,
    'attackData_configId': 50,
    'attackData_policyId': 50,
    'attackData_slowPostAction': 50,
    'attackData_custom': None,
    'botData_botScore': None,
    'clientData_appBundleId': 255,
    'clientData_appVersion': 50,
    'clientData_sdkVersion': 50,
    'clientData_telemetryType': 50,
    'geo_asn': None,
    'geo_city': 100,
    'geo_continent': 50,
    'geo_country': 50,
    'geo_regionCode': 50,
    'httpMessage_bytes': None,
    'httpMessage_host': 255,
    'httpMessage_method': 20,
    'httpMessage_path': 2048,
    'httpMessage_port': None,
    'httpMessage_protocol': 50,
    'httpMessage_query': None,
    'httpMessage_start': None,
    'httpMessage_status': None,
    'httpMessage_tls': 100,
    'userRiskData_allow': None,
    'userRiskData_general': 100,
    'userRiskData_originUserId': 255,
    'userRiskData_risk': 100,
    'userRiskData_score': None,
    'userRiskData_status': 100,
    'userRiskData_trust': 100,
    'userRiskData_username': 255,
    'userRiskData_uuid': 255,
}

CHILD_FIELD_LIMITS = {
    'rule_action': 4000,
    'rule_data': 4000,
    'rule_message': 4000,
    'rule_selector': 4000,
    'rule_tag': 4000,
    'rule_version': 4000,
    'rule_id': 4000,
}

def truncate_value(value, field_name, max_length):
    if value is None or max_length is None:
        return value
    # Handle bytes
    if isinstance(value, bytes):
        try:
            value = value.decode('utf-8', errors='replace')
        except Exception:
            value = str(value)
    # Handle list/dict (convert to str or None)
    if isinstance(value, (list, dict)):
        logging.warning(f"Field '{field_name}' received a {type(value).__name__}; converting to string: {value!r}")
        value = str(value)
    # Force everything else to string except int, float, bool
    if not isinstance(value, (str, int, float, bool)):
        value = str(value)
    # Now check length for string fields
    if isinstance(value, str) and len(value) > max_length:
        logging.warning(f"Value for '{field_name}' truncated to {max_length} chars. Original: {value[:200]!r}...")
        return value[:max_length]
    return value

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
    config["BATCH_SIZE"] = int(os.getenv("BATCH_SIZE", "10000"))
    config["CHILD_INSERT_WORKERS"] = int(os.getenv("CHILD_INSERT_WORKERS", "4"))
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
    try:
        prev_to = int(to_file.read_text().strip()) if to_file.exists() else now - 1000
    except Exception as e:
        logging.warning(f"Could not read or parse .akamai_to: {e}")
        prev_to = now - 1000
    from_time = prev_to
    to_time = now - 5
    logging.info(f"Fetching events from {from_time} to {to_time}")
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
    try:
        to_file.write_text(str(to_time+1))
    except Exception as e:
        logging.warning(f"Failed to write .akamai_to file: {e}")
    return events

def decode_and_split(value_string):
    seen = set()
    decoded_values = []
    if not value_string:
        return decoded_values
    try:
        decoded = urllib.parse.unquote(value_string)
        for val in decoded.split(";"):
            val = val.strip()
            if not val or val in seen:
                continue
            seen.add(val)
            try:
                val = base64.b64decode(val.encode("utf-8"), validate=True).decode("utf-8").strip()
            except Exception as e:
                logging.debug(f"Base64 decode error for value '{val[:50]}': {e}")
                pass
            decoded_values.append(val)
    except Exception as e:
        logging.warning(f"Decode error for value '{str(value_string)[:100]}': {e}")
    return decoded_values

def connect(config):
    logging.info("Connecting to MSSQL...")
    conn_str = (
        f"DRIVER={{{config['SQL_DRIVER']}}};"
        f"SERVER={config['SQL_SERVER']};"
        f"DATABASE={config['SQL_DATABASE']};"
        f"UID={config['SQL_USERNAME']};"
        f"PWD={config['SQL_PASSWORD']};"
        f"TrustServerCertificate=yes;Encrypt=yes;packet size=32767;"
    )
    conn = pyodbc.connect(conn_str, timeout=60)
    conn.autocommit = False
    return conn

def reconnect(config, retry_wait=5, max_retries=5):
    attempt = 0
    while True:
        try:
            logging.warning("Attempting to reconnect to MSSQL after connection failure...")
            conn = connect(config)
            cursor = conn.cursor()
            try:
                cursor.fast_executemany = True
            except Exception:
                pass
            cursor.execute("SELECT 1")
            cursor.fetchall()
            cursor.close()
            return conn
        except pyodbc.Error as e:
            attempt += 1
            logging.warning(f"Reconnect failed with error: {repr(e)}")
            if attempt > max_retries:
                logging.error(f"Failed to reconnect after {max_retries} tries: {e}")
                raise
            time.sleep(retry_wait)

def batch_insert(cursor, sql, data, config=None, batch_size=5000, table_name="", field_names=None):
    conn = cursor.connection
    for i in range(0, len(data), batch_size):
        chunk = data[i:i+batch_size]
        # DEBUG: Print field types and lengths for each row in this chunk before batch insert
        for rownum, row in enumerate(chunk):
            for idx, val in enumerate(row):
                field_label = field_names[idx] if field_names and idx < len(field_names) else str(idx)
                logging.debug(f"BATCH-INSERT: Table={table_name}, Row={rownum}, Field={field_label}, Type={type(val)}, Len={len(val) if isinstance(val, str) else 'n/a'}, Val={val!r}")
        retry = 0
        duplicates = 0
        truncation = 0
        while retry < 5:
            try:
                cursor.executemany(sql, chunk)
                conn.commit()
                break
            except pyodbc.OperationalError as e:
                logging.warning(f"pyodbc.OperationalError during insert: {repr(e)}")
                if "08S01" in str(e) or "timeout" in str(e).lower():
                    logging.warning(f"SQL connection lost or timed out ({e}); reconnecting and retrying...")
                    try:
                        cursor.close()
                        conn.close()
                    except Exception:
                        pass
                    new_conn = reconnect(config)
                    cursor = new_conn.cursor()
                    try:
                        cursor.fast_executemany = True
                    except Exception:
                        pass
                    conn = new_conn
                    retry += 1
                    continue
                else:
                    logging.exception(f"Operational error during insert into {table_name}:")
                    raise
            except pyodbc.IntegrityError as e:
                for row in chunk:
                    row_retries = 0
                    # DEBUG: Print field types and lengths before single row insert
                    for idx, val in enumerate(row):
                        field_label = field_names[idx] if field_names and idx < len(field_names) else str(idx)
                        logging.debug(f"SINGLE-INSERT: Table={table_name}, Field={field_label}, Type={type(val)}, Len={len(val) if isinstance(val, str) else 'n/a'}, Val={val!r}")
                    while row_retries < 5:
                        try:
                            cursor.execute(sql, row)
                            conn.commit()
                            break
                        except pyodbc.IntegrityError as single_e:
                            if "duplicate key" in str(single_e).lower() or "primary key" in str(single_e).lower():
                                duplicates += 1
                                break
                            elif "foreign key" in str(single_e).lower():
                                break
                            else:
                                logging.exception(f"Database error during per-row insert into {table_name}:")
                                break
                        except pyodbc.DataError as data_e:
                            if "22001" in str(data_e):
                                truncation += 1
                                if truncation == 1:
                                    logging.warning(f"String truncation (22001) error for a row in {table_name}; further occurrences in this batch will be skipped silently.")
                                break
                            else:
                                logging.error(f"DataError: {data_e}. Row was: {row}")
                                break
                        except pyodbc.OperationalError as single_e:
                            logging.warning(f"pyodbc.OperationalError during per-row insert: {repr(single_e)}")
                            if "08S01" in str(single_e) or "timeout" in str(single_e).lower():
                                logging.warning(f"SQL connection lost or timed out during per-row insert ({single_e}); reconnecting and retrying...")
                                try:
                                    cursor.close()
                                    conn.close()
                                except Exception:
                                    pass
                                new_conn = reconnect(config)
                                cursor = new_conn.cursor()
                                try:
                                    cursor.fast_executemany = True
                                except Exception:
                                    pass
                                conn = new_conn
                                row_retries += 1
                                continue
                            else:
                                logging.exception(f"Operational error during per-row insert into {table_name}:")
                                break
                        break
                break
        label = f" for table '{table_name}'" if table_name else ""
        logging.info(f"Committed batch {i + len(chunk)} / {len(data)}{label}")
        if duplicates > 0:
            logging.info(f"Skipped {duplicates} duplicate key(s) in {table_name} in this batch.")
        if truncation > 0:
            logging.warning(f"Skipped {truncation} row(s) in {table_name} due to string truncation in this batch.")
    try:
        cursor.close()
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass


def parallel_child_inserts(child_tables, config, child_columns):
    def child_insert_worker(args):
        table, rows = args
        if not rows:
            return
        conn = connect(config)
        try:
            cursor = conn.cursor()
            try:
                cursor.fast_executemany = True
            except Exception:
                pass
            column = child_columns[table]
            # FIELD SIZE VALIDATION/TRUNCATION FOR CHILD TABLES
            validated_rows = []
            for row in rows:
                request_id, val = row
                validated_val = truncate_value(val, column, CHILD_FIELD_LIMITS[column])
                validated_rows.append((truncate_value(request_id, 'requestId', FIELD_SIZE_LIMITS['requestId']), validated_val))
            sql = f"INSERT INTO {table} (requestId, {column}) VALUES (?, ?)"
            batch_insert(cursor, sql, validated_rows, config=config, table_name=table, field_names=['requestId', column])
        finally:
            try:
                conn.close()
            except Exception:
                pass
    with ThreadPoolExecutor(max_workers=config["CHILD_INSERT_WORKERS"]) as executor:
        executor.map(child_insert_worker, [(table, rows) for table, rows in child_tables.items() if rows])

def write_to_mssql(config, events):
    main_rows = []
    child_tables = {
        "akamai_attack_ruleActions": [],
        #"akamai_attack_ruleData": [],
        #"akamai_attack_ruleMessages": [],
        "akamai_attack_ruleSelectors": [],
        "akamai_attack_ruleTags": [],
        #"akamai_attack_ruleVersions": [],
        "akamai_attack_rules": [],
    }
    child_columns = {
        "akamai_attack_ruleActions": "rule_action",
        #"akamai_attack_ruleData": "rule_data",
        #"akamai_attack_ruleMessages": "rule_message",
        "akamai_attack_ruleSelectors": "rule_selector",
        "akamai_attack_ruleTags": "rule_tag",
        #"akamai_attack_ruleVersions": "rule_version",
        "akamai_attack_rules": "rule_id",
    }
    seen_request_ids = set()
    total = len(events)
    main_row_fields = [
        'requestId', 'format', 'type', 'version', 'responseSegment',
        'attackData_apiId', 'attackData_apiKey', 'attackData_clientIP',
        'attackData_clientReputation', 'attackData_configId', 'attackData_policyId',
        'attackData_slowPostAction', 'attackData_slowPostRate', 'attackData_custom',
        'botData_botScore',
        'clientData_appBundleId', 'clientData_appVersion', 'clientData_sdkVersion', 'clientData_telemetryType',
        'geo_asn', 'geo_city', 'geo_continent', 'geo_country', 'geo_regionCode',
        'httpMessage_bytes', 'httpMessage_host', 'httpMessage_method',
        'httpMessage_path', 'httpMessage_port', 'httpMessage_protocol',
        'httpMessage_query', 'httpMessage_start', 'httpMessage_status', 'httpMessage_tls',
        'userRiskData_allow', 'userRiskData_general', 'userRiskData_originUserId',
        'userRiskData_risk', 'userRiskData_score', 'userRiskData_status',
        'userRiskData_trust', 'userRiskData_username', 'userRiskData_uuid'
    ]
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
        row_dict = {
            'requestId': request_id,
            'format': event.get("format"),
            'type': event.get("type"),
            'version': event.get("version"),
            'responseSegment': event.get("responseSegment"),
            'attackData_apiId': ad.get("apiId"),
            'attackData_apiKey': ad.get("apiKey"),
            'attackData_clientIP': ad.get("clientIP"),
            'attackData_clientReputation': ad.get("clientReputation"),
            'attackData_configId': ad.get("configId"),
            'attackData_policyId': ad.get("policyId"),
            'attackData_slowPostAction': ad.get("slowPostAction"),
            'attackData_slowPostRate': ad.get("slowPostRate"),
            'attackData_custom': ad.get("custom"),
            'botData_botScore': bot.get("botScore"),
            'clientData_appBundleId': cd.get("appBundleId"),
            'clientData_appVersion': cd.get("appVersion"),
            'clientData_sdkVersion': cd.get("sdkVersion"),
            'clientData_telemetryType': cd.get("telemetryType"),
            'geo_asn': geo.get("asn"),
            'geo_city': geo.get("city"),
            'geo_continent': geo.get("continent"),
            'geo_country': geo.get("country"),
            'geo_regionCode': geo.get("regionCode"),
            'httpMessage_bytes': http.get("bytes"),
            'httpMessage_host': http.get("host"),
            'httpMessage_method': http.get("method"),
            'httpMessage_path': http.get("path"),
            'httpMessage_port': http.get("port"),
            'httpMessage_protocol': http.get("protocol"),
            'httpMessage_query': http.get("query"),
            'httpMessage_start': http.get("start"),
            'httpMessage_status': http.get("status"),
            'httpMessage_tls': http.get("tls"),
            'userRiskData_allow': urd.get("allow"),
            'userRiskData_general': urd.get("general"),
            'userRiskData_originUserId': urd.get("originUserId"),
            'userRiskData_risk': urd.get("risk"),
            'userRiskData_score': urd.get("score"),
            'userRiskData_status': urd.get("status"),
            'userRiskData_trust': urd.get("trust"),
            'userRiskData_username': urd.get("username"),
            'userRiskData_uuid': urd.get("uuid")
        }
        validated_row = []
        for fname in main_row_fields:
            val = row_dict[fname]
            maxlen = FIELD_SIZE_LIMITS.get(fname)
            validated_row.append(truncate_value(val, fname, maxlen))
        main_rows.append(tuple(validated_row))
        for table, column, val in [
            ("akamai_attack_ruleActions", "rule_action", ad.get("ruleActions")),
            #("akamai_attack_ruleData", "rule_data", ad.get("ruleData")),
            #("akamai_attack_ruleMessages", "rule_message", ad.get("ruleMessages")),
            ("akamai_attack_ruleSelectors", "rule_selector", ad.get("ruleSelectors")),
            ("akamai_attack_ruleTags", "rule_tag", ad.get("ruleTags")),
            #("akamai_attack_ruleVersions", "rule_version", ad.get("ruleVersions")),
            ("akamai_attack_rules", "rule_id", ad.get("rules")),
        ]:
            if not val:
                continue
            for v in decode_and_split(val):
                v_trunc = truncate_value(v, column, CHILD_FIELD_LIMITS[column])
                child_tables[table].append(
                    (truncate_value(request_id, 'requestId', FIELD_SIZE_LIMITS['requestId']), v_trunc)
                )
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
    conn = connect(config)
    try:
        cursor = conn.cursor()
        try:
            cursor.fast_executemany = True
        except Exception:
            pass
        batch_insert(cursor, main_sql, main_rows, config=config, batch_size=config["BATCH_SIZE"], table_name=config['SQL_TABLE'], field_names=main_row_fields)
    except Exception as e:
        logging.exception("Main table insert failed: %s", e)
    finally:
        try:
            conn.close()
        except Exception:
            pass
    parallel_child_inserts(child_tables, config, child_columns)
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
    try:
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
            return 0
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
            return 1
        return 0
    except Exception as e:
        logging.exception(f"Fatal error: {e}")
        return 2

if __name__ == "__main__":
    sys.exit(main())
