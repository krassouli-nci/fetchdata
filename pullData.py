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
import hashlib

import requests
import pyodbc
pyodbc.pooling = True   # Enable ODBC connection pooling globally

from akamai.edgegrid import EdgeGridAuth
from dotenv import load_dotenv

FIELD_SIZE_LIMITS = {
    'unique_id': 200,  # new composite key
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
    'attackData_slowPostRate': 50,
    'botData_botScore': 50,
    'clientData_appBundleId': 255,
    'clientData_appVersion': 50,
    'clientData_sdkVersion': 50,
    'clientData_telemetryType': 50,
    'geo_asn': 50,
    'geo_city': 100,
    'geo_continent': 50,
    'geo_country': 50,
    'geo_regionCode': 50,
    'httpMessage_bytes': 50,
    'httpMessage_host': 255,
    'httpMessage_method': 20,
    'httpMessage_path': 2048,
    'httpMessage_port': 50,
    'httpMessage_protocol': 50,
    'httpMessage_query': None,  # NVARCHAR(MAX)
    'httpMessage_start': 50,
    'httpMessage_status': 50,
    'httpMessage_tls': 100,
    'userRiskData_allow': 10,
    'userRiskData_general': 100,
    'userRiskData_originUserId': 255,
    'userRiskData_risk': 100,
    'userRiskData_score': 50,
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

def force_string(val):
    if val is None:
        return None
    s = str(val)
    if s.strip() == "":
        return None
    return s

def truncate_value(value, field_name, max_length):
    value = force_string(value)
    if value is None:
        return None
    if max_length is not None and len(value) > max_length:
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
    config["SQL_DRIVER"] = os.getenv("SQL_DRIVER", "ODBC Driver 18 for SQL Server")
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

def fetch_events(session, host, config_id, limit=20000):
    url = f"https://{host}/siem/v1/configs/{config_id}"
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
    try:
        to_file.write_text(str(to_time + 1))
    except Exception as e:
        logging.warning(f"Failed to write .akamai_to file: {e}")

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
    trusted = os.getenv("SQL_TRUSTED_CONNECTION", "false").lower() == "true"
    if trusted:
        conn_str = (
            f"DRIVER={{{config['SQL_DRIVER']}}};"
            f"SERVER={config['SQL_SERVER']};"
            f"DATABASE={config['SQL_DATABASE']};"
            f"Trusted_Connection=yes;"
            f"TrustServerCertificate=yes;Encrypt=yes;packet size=32767;"
        )
    else:
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

def deduplicate_by_unique_id(rows, key_index=0):
    seen = set()
    deduped = []
    for row in rows:
        uid = row[key_index]
        if uid not in seen:
            deduped.append(row)
            seen.add(uid)
    return deduped

def deduplicate_child_rows(rows):
    seen = set()
    deduped = []
    for row in rows:
        key = (row[0], row[1])
        if key not in seen:
            deduped.append(row)
            seen.add(key)
    return deduped

def batch_insert(
    cursor,
    sql,
    data,
    config=None,
    batch_size=5000,
    table_name="akamai_events",
    field_names=None
):
    conn = cursor.connection
    total = len(data)
    total_inserted = 0
    for i in range(0, total, batch_size):
        chunk = data[i:i+batch_size]
        expected_length = len(field_names) if field_names else None
        for rownum, row in enumerate(chunk):
            row_length = len(row) if isinstance(row, (tuple, list)) else len(field_names)
            if expected_length is not None and row_length != expected_length:
                logging.error(f"[VALIDATION ERROR] Row {rownum} length {row_length} does not match expected {expected_length}: {row}")
                raise Exception(f"Row {rownum} length {row_length} does not match expected {expected_length}: {row}")
        retry = 0
        while retry < 5:
            try:
                try:
                    cursor.fast_executemany = True
                except Exception:
                    pass
                logging.info(f"Inserting chunk of {len(chunk)} rows into table {table_name}...")
                cursor.executemany(sql, chunk)
                conn.commit()
                total_inserted += len(chunk)
                break
            except pyodbc.IntegrityError as e:
                if 'PRIMARY KEY' in str(e) or 'duplicate' in str(e).lower():
                    logging.warning(f"Duplicate key error in chunk (some or all rows already exist) for {table_name}: {e}")
                    conn.rollback()
                    break
                else:
                    logging.error(f"Integrity error in {table_name}: {e}")
                    conn.rollback()
                    retry += 1
                    time.sleep(2)
            except Exception as e:
                logging.error(f"Error during insert for {table_name}: {e}")
                conn.rollback()
                retry += 1
                time.sleep(2)
        logging.info(f"Committed batch {min(i+len(chunk), total)} / {total} for table '{table_name}'")
    logging.info(f"Batch insert finished for {table_name}. {total_inserted} rows attempted (duplicates skipped by SQL Server).")

def parallel_child_inserts(child_tables, config, child_columns, allowed_unique_ids=None):
    def child_insert_worker(args):
        table, rows = args
        if not rows:
            return
        if allowed_unique_ids is not None:
            rows = [row for row in rows if row[0] in allowed_unique_ids]
        if not rows:
            return
        rows = deduplicate_child_rows(rows)
        conn = connect(config)
        try:
            cursor = conn.cursor()
            try:
                cursor.fast_executemany = True
                logging.info("fast_executemany enabled for this platform/driver (child table).")
            except Exception:
                logging.info("fast_executemany not available (child table); using standard executemany.")
            column = child_columns[table]
            validated_rows = []
            for row in rows:
                unique_id, val = row
                validated_val = truncate_value(val, column, CHILD_FIELD_LIMITS[column])
                validated_rows.append((truncate_value(unique_id, 'unique_id', FIELD_SIZE_LIMITS['unique_id']), validated_val))
            sql = f"INSERT INTO {table} (unique_id, {column}) VALUES (?, ?)"
            batch_insert(cursor, sql, validated_rows, config=config, table_name=table, field_names=['unique_id', column])
        finally:
            try:
                conn.close()
            except Exception:
                pass
    with ThreadPoolExecutor(max_workers=config["CHILD_INSERT_WORKERS"]) as executor:
        executor.map(child_insert_worker, [(table, rows) for table, rows in child_tables.items() if rows])

def get_existing_unique_ids(config, unique_ids):
    """
    Checks which unique_ids exist in the parent table after attempted insert.
    Only these should be used for child inserts.
    """
    if not unique_ids:
        return set()
    conn = connect(config)
    try:
        cursor = conn.cursor()
        # SQL IN limit is 2100 items, chunk if needed
        result = set()
        unique_ids = list(unique_ids)
        chunk_size = 1000
        for i in range(0, len(unique_ids), chunk_size):
            chunk = unique_ids[i:i+chunk_size]
            placeholders = ','.join('?' for _ in chunk)
            sql = f"SELECT unique_id FROM {config['SQL_TABLE']} WHERE unique_id IN ({placeholders})"
            cursor.execute(sql, chunk)
            rows = cursor.fetchall()
            result.update(row[0] for row in rows)
        return result
    finally:
        try:
            conn.close()
        except Exception:
            pass

def compute_unique_id(event):
    parts = [
        str(event.get("type", "")),
        str(event.get("format", "")),
        str(event.get("version", "")),
        str(event.get("responseSegment", "")),
        str(event.get("attackData", {}).get("configId", "")),
        str(event.get("httpMessage", {}).get("requestId", "")),
        str(event.get("httpMessage", {}).get("start", "")),
    ]
    composite = "||".join(parts)
    composite += "||" + json.dumps(event, sort_keys=True)
    h = hashlib.sha256(composite.encode("utf-8")).hexdigest()
    return h[:FIELD_SIZE_LIMITS['unique_id']]

def write_to_mssql(config, events):
    main_rows = []
    child_tables = {
        "akamai_attack_ruleActions": [],
        "akamai_attack_ruleSelectors": [],
        "akamai_attack_ruleTags": [],
        "akamai_attack_rules": [],
    }
    child_columns = {
        "akamai_attack_ruleActions": "rule_action",
        "akamai_attack_ruleSelectors": "rule_selector",
        "akamai_attack_ruleTags": "rule_tag",
        "akamai_attack_rules": "rule_id",
    }
    seen_unique_ids = set()
    total = len(events)
    main_row_fields = [
        'unique_id', 'requestId', 'format', 'type', 'version', 'responseSegment',
        'attackData_apiId', 'attackData_apiKey', 'attackData_clientIP',
        'attackData_clientReputation', 'attackData_configId', 'attackData_policyId',
        'attackData_slowPostAction', 'attackData_slowPostRate',
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
    row_unique_ids = []
    child_table_raw_rows = {k: [] for k in child_tables}
    for idx, event in enumerate(events, 1):
        ad = event.get("attackData", {})
        bot = event.get("botData", {})
        cd = event.get("clientData", {})
        geo = event.get("geo", {})
        http = event.get("httpMessage", {})
        urd = event.get("userRiskData", {})
        unique_id = compute_unique_id(event)
        if not unique_id or unique_id in seen_unique_ids:
            continue
        seen_unique_ids.add(unique_id)
        row_unique_ids.append(unique_id)
        row_dict = {
            'unique_id': unique_id,
            'requestId': http.get("requestId"),
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
            val = row_dict.get(fname)
            maxlen = FIELD_SIZE_LIMITS.get(fname) if fname in FIELD_SIZE_LIMITS else None
            validated_row.append(truncate_value(val, fname, maxlen))
        main_rows.append(tuple(validated_row))
        for table, column, val in [
            ("akamai_attack_ruleActions", "rule_action", ad.get("ruleActions")),
            ("akamai_attack_ruleSelectors", "rule_selector", ad.get("ruleSelectors")),
            ("akamai_attack_ruleTags", "rule_tag", ad.get("ruleTags")),
            ("akamai_attack_rules", "rule_id", ad.get("rules")),
        ]:
            if not val:
                continue
            for v in decode_and_split(val):
                v_trunc = truncate_value(v, column, CHILD_FIELD_LIMITS[column])
                child_table_raw_rows[table].append(
                    (unique_id, v_trunc)
                )
        if idx % 1000 == 0 or idx == total:
            percent = (idx / total) * 100
            logging.info(f"Progress: {idx}/{total} ({percent:.1f}%)")

    deduped_rows = deduplicate_by_unique_id(main_rows, key_index=0)
    attempted_insert_ids = set(row[0] for row in deduped_rows)
    if len(deduped_rows) < len(main_rows):
        logging.warning(f"Deduplicated {len(main_rows) - len(deduped_rows)} duplicate unique_ids before insert.")
    conn = connect(config)
    actually_inserted_ids = set()
    try:
        cursor = conn.cursor()
        try:
            cursor.fast_executemany = True
            logging.info("fast_executemany enabled for this platform/driver (main table).")
        except Exception:
            logging.info("fast_executemany not available (main table); using standard executemany.")
        main_sql = f"""
            INSERT INTO {config['SQL_TABLE']} (
                unique_id, requestId, format, type, version, responseSegment,
                attackData_apiId, attackData_apiKey, attackData_clientIP,
                attackData_clientReputation, attackData_configId, attackData_policyId,
                attackData_slowPostAction, attackData_slowPostRate,
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
        batch_insert(cursor, main_sql, deduped_rows, config=config, batch_size=config["BATCH_SIZE"], table_name=config['SQL_TABLE'], field_names=main_row_fields)
        # After commit, query the parent table for those unique_ids we just tried to insert.
        actually_inserted_ids = get_existing_unique_ids(config, attempted_insert_ids)
    except Exception as e:
        logging.exception("Main table insert failed: %s", e)
    finally:
        try:
            conn.close()
        except Exception:
            pass
    # Only insert child rows whose unique_id is actually present in the parent table
    for table in child_tables:
        child_tables[table] = [row for row in child_table_raw_rows[table] if row[0] in actually_inserted_ids]
    parallel_child_inserts(child_tables, config, child_columns, allowed_unique_ids=actually_inserted_ids)
    logging.info(f"Inserted {len(actually_inserted_ids)} parent events and child records into MSSQL.")

def main():
    try:
        setup_logging()
        config = load_config()
        session = create_session(
            config["AKAMAI_CLIENT_TOKEN"],
            config["AKAMAI_CLIENT_SECRET"],
            config["AKAMAI_ACCESS_TOKEN"],
        )
        total_events = 0
        for batch_events in fetch_events(session, config["AKAMAI_HOST"], config["AKAMAI_SIEM_CONFIG_ID"]):
            if not batch_events:
                continue
            total_events += len(batch_events)
            logging.info(f"Processing and inserting {len(batch_events)} events in this batch (Total so far: {total_events})")
            write_to_mssql(config, batch_events)
            del batch_events
            import gc; gc.collect()
        if total_events == 0:
            logging.info("No events retrieved.")
            return 0
        logging.info(f"Total events processed: {total_events}")
        return 0
    except Exception as e:
        logging.exception(f"Fatal error: {e}")
        return 2

if __name__ == "__main__":
    sys.exit(main())
