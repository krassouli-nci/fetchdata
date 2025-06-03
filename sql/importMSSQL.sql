-- 1. Drop child tables first (order matters for FK constraints)
DROP TABLE IF EXISTS akamai_events;
DROP TABLE IF EXISTS akamai_attack_rules;
DROP TABLE IF EXISTS akamai_attack_ruleTags;
DROP TABLE IF EXISTS akamai_attack_ruleSelectors;
DROP TABLE IF EXISTS akamai_attack_ruleActions;

-- 2. Drop main table
DROP TABLE IF EXISTS akamai_events;

-- 3. Create main table with unique_id as PRIMARY KEY, requestId as regular field
CREATE TABLE akamai_events (
    unique_id NVARCHAR(200) PRIMARY KEY, -- Composite key
    requestId VARCHAR(100),
    format NVARCHAR(50),
    type NVARCHAR(50),
    version NVARCHAR(50),
    responseSegment NVARCHAR(50),
    attackData_apiId NVARCHAR(255),
    attackData_apiKey NVARCHAR(255),
    attackData_clientIP NVARCHAR(50),
    attackData_clientReputation NVARCHAR(50),
    attackData_configId NVARCHAR(50),
    attackData_policyId NVARCHAR(50),
    attackData_slowPostAction NVARCHAR(50),
    attackData_slowPostRate NVARCHAR(50),
    botData_botScore NVARCHAR(50),
    clientData_appBundleId NVARCHAR(255),
    clientData_appVersion NVARCHAR(50),
    clientData_sdkVersion NVARCHAR(50),
    clientData_telemetryType NVARCHAR(50),
    geo_asn NVARCHAR(50),
    geo_city NVARCHAR(100),
    geo_continent NVARCHAR(50),
    geo_country NVARCHAR(50),
    geo_regionCode NVARCHAR(50),
    httpMessage_bytes NVARCHAR(50),
    httpMessage_host NVARCHAR(255),
    httpMessage_method NVARCHAR(20),
    httpMessage_path NVARCHAR(2048),
    httpMessage_port NVARCHAR(50),
    httpMessage_protocol NVARCHAR(50),
    httpMessage_query NVARCHAR(MAX),
    httpMessage_start NVARCHAR(50),
    httpMessage_status NVARCHAR(50),
    httpMessage_tls NVARCHAR(100),
    userRiskData_allow NVARCHAR(10),
    userRiskData_general NVARCHAR(100),
    userRiskData_originUserId NVARCHAR(255),
    userRiskData_risk NVARCHAR(100),
    userRiskData_score NVARCHAR(50),
    userRiskData_status NVARCHAR(100),
    userRiskData_trust NVARCHAR(100),
    userRiskData_username NVARCHAR(255),
    userRiskData_uuid NVARCHAR(255),
    created_at DATETIME2 DEFAULT SYSUTCDATETIME(),
    modified_at DATETIME2 DEFAULT SYSUTCDATETIME()
);

-- 4. Child tables now use unique_id as FK and have created_at, modified_at columns
CREATE TABLE akamai_attack_ruleActions (
    unique_id NVARCHAR(200) NOT NULL,
    rule_action NVARCHAR(4000) NULL,
    created_at DATETIME2 DEFAULT SYSUTCDATETIME(),
    modified_at DATETIME2 DEFAULT SYSUTCDATETIME(),
    FOREIGN KEY (unique_id) REFERENCES akamai_events(unique_id)
);

CREATE TABLE akamai_attack_ruleSelectors (
    unique_id NVARCHAR(200) NOT NULL,
    rule_selector NVARCHAR(4000) NULL,
    created_at DATETIME2 DEFAULT SYSUTCDATETIME(),
    modified_at DATETIME2 DEFAULT SYSUTCDATETIME(),
    FOREIGN KEY (unique_id) REFERENCES akamai_events(unique_id)
);

CREATE TABLE akamai_attack_ruleTags (
    unique_id NVARCHAR(200) NOT NULL,
    rule_tag NVARCHAR(4000) NULL,
    created_at DATETIME2 DEFAULT SYSUTCDATETIME(),
    modified_at DATETIME2 DEFAULT SYSUTCDATETIME(),
    FOREIGN KEY (unique_id) REFERENCES akamai_events(unique_id)
);

CREATE TABLE akamai_attack_rules (
    unique_id NVARCHAR(200) NOT NULL,
    rule_id NVARCHAR(4000) NULL,
    created_at DATETIME2 DEFAULT SYSUTCDATETIME(),
    modified_at DATETIME2 DEFAULT SYSUTCDATETIME(),
    FOREIGN KEY (unique_id) REFERENCES akamai_events(unique_id)
);
