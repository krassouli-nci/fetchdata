UPDATE akamai_attack_ruleActions
    SET created_at = SYSUTCDATETIME(), modified_at = SYSUTCDATETIME()
    WHERE created_at IS NULL OR modified_at IS NULL;

UPDATE akamai_attack_ruleSelectors
    SET created_at = SYSUTCDATETIME(), modified_at = SYSUTCDATETIME()
    WHERE created_at IS NULL OR modified_at IS NULL;

UPDATE akamai_attack_ruleTags
    SET created_at = SYSUTCDATETIME(), modified_at = SYSUTCDATETIME()
    WHERE created_at IS NULL OR modified_at IS NULL;

UPDATE akamai_attack_rules
    SET created_at = SYSUTCDATETIME(), modified_at = SYSUTCDATETIME()
    WHERE created_at IS NULL OR modified_at IS NULL;
