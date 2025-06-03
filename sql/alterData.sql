ALTER TABLE akamai_attack_ruleActions
    ADD created_at DATETIME2 NULL, modified_at DATETIME2 NULL;

ALTER TABLE akamai_attack_ruleSelectors
    ADD created_at DATETIME2 NULL, modified_at DATETIME2 NULL;

ALTER TABLE akamai_attack_ruleTags
    ADD created_at DATETIME2 NULL, modified_at DATETIME2 NULL;

ALTER TABLE akamai_attack_rules
    ADD created_at DATETIME2 NULL, modified_at DATETIME2 NULL;

