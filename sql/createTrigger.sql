--- 5. Trigger to update modified_at timestamp
DROP TRIGGER IF EXISTS trg_UpdateModifiedAt ON akamai_events;
GO
CREATE TRIGGER trg_UpdateModifiedAt
ON akamai_events
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE akamai_events
    SET modified_at = SYSUTCDATETIME()
    FROM akamai_events ae
    INNER JOIN inserted i ON ae.unique_id = i.unique_id;
END;
GO


-- Triggers to update modified_at on child tables after UPDATE

-- 1. akamai_attack_ruleActions
DROP TRIGGER IF EXISTS dbo.trg_UpdateModifiedAt_ruleActions;
GO
CREATE TRIGGER dbo.trg_UpdateModifiedAt_ruleActions
ON dbo.akamai_attack_ruleActions
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE ara
    SET modified_at = SYSUTCDATETIME()
    FROM dbo.akamai_attack_ruleActions ara
    INNER JOIN inserted i
        ON ara.unique_id = i.unique_id
        AND ara.rule_action = i.rule_action;
END;
GO

-- 2. akamai_attack_ruleSelectors
DROP TRIGGER IF EXISTS dbo.trg_UpdateModifiedAt_ruleSelectors;
GO
CREATE TRIGGER dbo.trg_UpdateModifiedAt_ruleSelectors
ON dbo.akamai_attack_ruleSelectors
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE ars
    SET modified_at = SYSUTCDATETIME()
    FROM dbo.akamai_attack_ruleSelectors ars
    INNER JOIN inserted i
        ON ars.unique_id = i.unique_id
        AND ars.rule_selector = i.rule_selector;
END;
GO

-- 3. akamai_attack_ruleTags
DROP TRIGGER IF EXISTS dbo.trg_UpdateModifiedAt_ruleTags;
GO
CREATE TRIGGER dbo.trg_UpdateModifiedAt_ruleTags
ON dbo.akamai_attack_ruleTags
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE art
    SET modified_at = SYSUTCDATETIME()
    FROM dbo.akamai_attack_ruleTags art
    INNER JOIN inserted i
        ON art.unique_id = i.unique_id
        AND art.rule_tag = i.rule_tag;
END;
GO

-- 4. akamai_attack_rules
DROP TRIGGER IF EXISTS dbo.trg_UpdateModifiedAt_rules;
GO
CREATE TRIGGER dbo.trg_UpdateModifiedAt_rules
ON dbo.akamai_attack_rules
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE ar
    SET modified_at = SYSUTCDATETIME()
    FROM dbo.akamai_attack_rules ar
    INNER JOIN inserted i
        ON ar.unique_id = i.unique_id
        AND ar.rule_id = i.rule_id;
END;
GO
