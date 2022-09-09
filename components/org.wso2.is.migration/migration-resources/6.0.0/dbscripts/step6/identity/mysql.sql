DROP PROCEDURE IF EXISTS ALTER_IDN_OAUTH2_DEVICE_FLOW;

DELIMITER $$
CREATE PROCEDURE ALTER_IDN_OAUTH2_DEVICE_FLOW()
BEGIN
    IF EXISTS(SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='IDN_OAUTH2_DEVICE_FLOW') THEN
        IF NOT EXISTS(SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='IDN_OAUTH2_DEVICE_FLOW' AND COLUMN_NAME='QUANTIFIER') THEN
            ALTER TABLE IDN_OAUTH2_DEVICE_FLOW
                ADD COLUMN QUANTIFIER INTEGER DEFAULT 0 NOT NULL,
                DROP INDEX USER_CODE,
                ADD CONSTRAINT USRCDE_QNTFR_CONSTRAINT UNIQUE (USER_CODE, QUANTIFIER);
        END IF;
    END IF;
END $$
DELIMITER ;

CALL ALTER_IDN_OAUTH2_DEVICE_FLOW();
DROP PROCEDURE ALTER_IDN_OAUTH2_DEVICE_FLOW;

START TRANSACTION;
UPDATE IDP_METADATA SET NAME = 'account.lock.handler.lock.on.max.failed.attempts.enable'
WHERE NAME = 'account.lock.handler.enable';
COMMIT;

CREATE TABLE IF NOT EXISTS IDN_SECRET_TYPE (
    ID VARCHAR(255) NOT NULL,
    NAME VARCHAR(255) NOT NULL,
    DESCRIPTION VARCHAR(1023) NULL,
    PRIMARY KEY (ID),
    CONSTRAINT SECRET_TYPE_NAME_CONSTRAINT UNIQUE (NAME)
) ENGINE INNODB;

CREATE TABLE IF NOT EXISTS IDN_SECRET (
    ID VARCHAR(255) NOT NULL,
    TENANT_ID INT NOT NULL,
    SECRET_NAME VARCHAR(255) NOT NULL,
    SECRET_VALUE VARCHAR(8000) NOT NULL,
    CREATED_TIME TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    LAST_MODIFIED TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    TYPE_ID       VARCHAR(255) NOT NULL,
    DESCRIPTION VARCHAR(1023) NULL,
    PRIMARY KEY (ID),
    FOREIGN KEY (TYPE_ID) REFERENCES IDN_SECRET_TYPE(ID) ON DELETE CASCADE,
    UNIQUE (SECRET_NAME, TENANT_ID, TYPE_ID)
) ENGINE INNODB;

INSERT INTO IDN_SECRET_TYPE (ID, NAME, DESCRIPTION) VALUES
('1358bdbf-e0cc-4268-a42c-c3e0960e13f0', 'ADAPTIVE_AUTH_CALL_CHOREO', 'Secret type to uniquely identify secrets relevant to callChoreo adaptive auth function');

INSERT IGNORE INTO IDN_CONFIG_TYPE (ID, NAME, DESCRIPTION)
VALUES ('669b99ca-cdb0-44a6-8cae-babed3b585df', 'Publisher', 'A resource type to keep the event publisher configurations');

