# Akamai SIEM Event Processor

This Python project retrieves security event logs from the Akamai SIEM API, decodes and processes the data, and stores it in an Azure-hosted MSSQL database or outputs grouped summary reports as text files. The script includes logic for handling base64-encoded fields and batching SQL inserts with related child tables.

## Features

- Authenticated Akamai API access using EdgeGrid
- Time-based pagination with `.akamai_to` tracking
- Decoding of rule actions and tags
- Optional grouping summary output (plain text)
- SQL Server insert with support for child tables and batching
- Logging to a dedicated `logs/` directory

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/your-org/akamai-siem-processor.git
cd akamai-siem-processor
```

### 2. Create and activate a virtual environment

#### macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Windows (CMD)

```cmd
python -m venv venv
venv\Scripts\activate.bat
```

#### Windows (PowerShell)

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root with the following variables:

```env
AKAMAI_CLIENT_TOKEN=your_client_token
AKAMAI_CLIENT_SECRET=your_client_secret
AKAMAI_ACCESS_TOKEN=your_access_token
AKAMAI_HOST=your_akamai_host
AKAMAI_SIEM_CONFIG_ID=your_config_id

SQL_SERVER=your_sql_server.database.windows.net
SQL_DATABASE=akamai_logs
SQL_USERNAME=your_sql_user
SQL_PASSWORD=your_sql_password
SQL_DRIVER=ODBC Driver 17 for SQL Server
SQL_TABLE=akamai_events

OUTPUT_MODE=sql   # Use 'sql' to store in MSSQL, or 'txt' for summary file output
```

## Running the Script

Run the main script (replace `your_script_name.py` with the actual filename):

```bash
python your_script_name.py
```

- Logs are saved to the `logs/` folder.
- If `OUTPUT_MODE=sql`, events are written to MSSQL.
- If `OUTPUT_MODE=txt`, a summary file is generated in the `output/` directory.

## Database Setup

To create the required MSSQL tables and trigger, run the SQL script located at `sql/importMSSQL.sql` in your Azure SQL database.

## Project Structure

```
logs/                # Application logs
output/              # Grouped output files (if OUTPUT_MODE=txt)
sql/
  └── importMSSQL.sql   # SQL schema and trigger
.env                # Environment variables (excluded from version control)
.gitignore          # Common excludes (.env, logs, venv, output, etc.)
your_script_name.py # Main script
```

## Notes

- `.akamai_to` is used to track the last fetched timestamp.
- Duplicate `requestId`s are de-duplicated per run.
- SQL inserts are batched and handle key conflicts gracefully.
