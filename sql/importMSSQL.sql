-- 1. Drop child tables first
DROP TABLE IF EXISTS akamai_httpMessage_responseHeaders;
DROP TABLE IF EXISTS akamai_httpMessage_requestHeaders;
DROP TABLE IF EXISTS akamai_attack_rules;
DROP TABLE IF EXISTS akamai_attack_ruleVersions;
DROP TABLE IF EXISTS akamai_attack_ruleTags;
DROP TABLE IF EXISTS akamai_attack_ruleSelectors;
DROP TABLE IF EXISTS akamai_attack_ruleMessages;
DROP TABLE IF EXISTS akamai_attack_ruleData;
DROP TABLE IF EXISTS akamai_attack_ruleActions;

-- 2. Drop main table
DROP TABLE IF EXISTS akamai_events;

-- 3. Create main table with requestId as PRIMARY KEY

CREATE TABLE akamai_events (
    requestId VARCHAR(100) PRIMARY KEY,
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
    attackData_slowPostRate FLOAT,
    attackData_custom NVARCHAR(MAX),

    botData_botScore INT,

    clientData_appBundleId NVARCHAR(255),
    clientData_appVersion NVARCHAR(50),
    clientData_sdkVersion NVARCHAR(50),
    clientData_telemetryType NVARCHAR(50),

    geo_asn INT,
    geo_city NVARCHAR(100),
    geo_continent NVARCHAR(50),
    geo_country NVARCHAR(50),
    geo_regionCode NVARCHAR(50),

    httpMessage_bytes BIGINT,
    httpMessage_host NVARCHAR(255),
    httpMessage_method NVARCHAR(20),
    httpMessage_path NVARCHAR(2048),
    httpMessage_port INT,
    httpMessage_protocol NVARCHAR(50),
    httpMessage_query NVARCHAR(MAX),
    httpMessage_start BIGINT,
    httpMessage_status INT,
    httpMessage_tls NVARCHAR(100),

    userRiskData_allow BIT,
    userRiskData_general NVARCHAR(100),
    userRiskData_originUserId NVARCHAR(255),
    userRiskData_risk NVARCHAR(100),
    userRiskData_score INT,
    userRiskData_status NVARCHAR(100),
    userRiskData_trust NVARCHAR(100),
    userRiskData_username NVARCHAR(255),
    userRiskData_uuid NVARCHAR(255),

    created_at DATETIME2 DEFAULT SYSUTCDATETIME(),
    modified_at DATETIME2 DEFAULT SYSUTCDATETIME()
);

-- 4. Child tables using requestId as FK
CREATE TABLE akamai_attack_ruleActions (
    requestId VARCHAR(100) NOT NULL,
    rule_action VARCHAR(4000) NULL,
    FOREIGN KEY (requestId) REFERENCES akamai_events(requestId)
);

CREATE TABLE akamai_attack_ruleData (
    requestId VARCHAR(100) NOT NULL,
    rule_data VARCHAR(4000) NULL,
    FOREIGN KEY (requestId) REFERENCES akamai_events(requestId)
);

CREATE TABLE akamai_attack_ruleMessages (
    requestId VARCHAR(100) NOT NULL,
    rule_message VARCHAR(4000) NULL,
    FOREIGN KEY (requestId) REFERENCES akamai_events(requestId)
);

CREATE TABLE akamai_attack_ruleSelectors (
    requestId VARCHAR(100) NOT NULL,
    rule_selector VARCHAR(4000) NULL,
    FOREIGN KEY (requestId) REFERENCES akamai_events(requestId)
);

CREATE TABLE akamai_attack_ruleTags (
    requestId VARCHAR(100) NOT NULL,
    rule_tag VARCHAR(4000) NULL,
    FOREIGN KEY (requestId) REFERENCES akamai_events(requestId)
);

CREATE TABLE akamai_attack_ruleVersions (
    requestId VARCHAR(100) NOT NULL,
    rule_version VARCHAR(4000) NULL,
    FOREIGN KEY (requestId) REFERENCES akamai_events(requestId)
);

CREATE TABLE akamai_attack_rules (
    requestId VARCHAR(100) NOT NULL,
    rule_id VARCHAR(4000) NULL,
    FOREIGN KEY (requestId) REFERENCES akamai_events(requestId)
);

CREATE TRIGGER trg_UpdateModifiedAt
ON akamai_events
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE akamai_events
    SET modified_at = SYSUTCDATETIME()
    FROM akamai_events ae
    INNER JOIN inserted i ON ae.requestId = i.requestId;
END;