DROP ALIAS IF EXISTS ALTER_UM_USER;
CREATE ALIAS ALTER_UM_USER AS $$ void alterUmUser(final Connection conn) throws SQLException { String const_name = ""; PreparedStatement ps = conn.prepareStatement("SELECT tc.CONSTRAINT_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc ON tc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME WHERE tc.TABLE_NAME ='UM_USER' AND tc.CONSTRAINT_TYPE = 'UNIQUE' AND kcu.COLUMN_NAME ='UM_USER_ID'"); ResultSet results =  ps.executeQuery(); while (results.next()) { const_name  = results.getString("CONSTRAINT_NAME"); } if (!const_name.equals("")) { ps = conn.prepareStatement("ALTER TABLE UM_USER DROP CONSTRAINT " + const_name); ps.execute(); } ps = conn.prepareStatement("ALTER TABLE UM_USER ADD UNIQUE(UM_USER_ID)"); ps.execute(); ps = conn.prepareStatement("SELECT tc.CONSTRAINT_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc ON tc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME WHERE tc.TABLE_NAME ='UM_USER' AND tc.CONSTRAINT_TYPE = 'UNIQUE' AND kcu.COLUMN_NAME ='UM_USER_NAME'"); results =  ps.executeQuery(); if (results.next() == false) { ps = conn.prepareStatement("ALTER TABLE UM_USER ADD UNIQUE(UM_USER_NAME,UM_TENANT_ID)"); ps.execute(); } } $$;

CALL ALTER_UM_USER();

DROP ALIAS IF EXISTS ALTER_UM_USER;

CREATE UNIQUE INDEX IF NOT EXISTS INDEX_UM_USERNAME_UM_TENANT_ID ON UM_USER(UM_USER_NAME, UM_TENANT_ID);

ALTER TABLE UM_TENANT ADD UM_ORG_UUID VARCHAR(36) DEFAULT NULL;

------------------------ ORGANIZATION MANAGEMENT TABLES -------------------------

CREATE TABLE IF NOT EXISTS UM_ORG (
    UM_ID VARCHAR(36) NOT NULL,
    UM_ORG_NAME VARCHAR(255) NOT NULL,
    UM_ORG_DESCRIPTION VARCHAR(1024),
    UM_CREATED_TIME TIMESTAMP NOT NULL,
    UM_LAST_MODIFIED TIMESTAMP NOT NULL,
    UM_STATUS VARCHAR(255) DEFAULT 'ACTIVE' NOT NULL,
    UM_PARENT_ID VARCHAR(36),
    UM_ORG_TYPE VARCHAR(100) NOT NULL,
    PRIMARY KEY (UM_ID),
    FOREIGN KEY (UM_PARENT_ID) REFERENCES UM_ORG(UM_ID) ON DELETE CASCADE
);

INSERT INTO UM_ORG(UM_ID, UM_ORG_NAME, UM_ORG_DESCRIPTION, UM_CREATED_TIME, UM_LAST_MODIFIED, UM_STATUS, UM_ORG_TYPE)
SELECT UM_ID, UM_ORG_NAME, UM_ORG_DESCRIPTION, UM_CREATED_TIME, UM_LAST_MODIFIED, UM_STATUS, UM_ORG_TYPE FROM (
	SELECT
	    '10084a8d-113f-4211-a0d5-efe36b082211' AS UM_ID,
	    'Super' AS UM_ORG_NAME,
            'This is the super organization.' AS UM_ORG_DESCRIPTION,
	    CURRENT_TIMESTAMP AS UM_CREATED_TIME,
	    CURRENT_TIMESTAMP AS UM_LAST_MODIFIED,
	    'ACTIVE' AS UM_STATUS,
	    'TENANT' AS UM_ORG_TYPE
) S
WHERE NOT EXISTS (SELECT * FROM UM_ORG org WHERE org.UM_ID = S.UM_ID);

CREATE TABLE IF NOT EXISTS UM_ORG_ATTRIBUTE (
    UM_ID INTEGER NOT NULL AUTO_INCREMENT,
    UM_ORG_ID VARCHAR(36) NOT NULL,
    UM_ATTRIBUTE_KEY VARCHAR(255) NOT NULL,
    UM_ATTRIBUTE_VALUE VARCHAR(512),
    PRIMARY KEY (UM_ID),
    UNIQUE (UM_ORG_ID, UM_ATTRIBUTE_KEY),
    FOREIGN KEY (UM_ORG_ID) REFERENCES UM_ORG(UM_ID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS UM_ORG_ROLE (
    UM_ROLE_ID VARCHAR(255) NOT NULL,
    UM_ROLE_NAME VARCHAR(255) NOT NULL,
    UM_ORG_ID VARCHAR(36) NOT NULL,
    PRIMARY KEY(UM_ROLE_ID),
    CONSTRAINT FK_UM_ORG_ROLE_UM_ORG FOREIGN KEY (UM_ORG_ID) REFERENCES UM_ORG (UM_ID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS UM_ORG_PERMISSION(
    UM_ID INTEGER NOT NULL AUTO_INCREMENT,
    UM_RESOURCE_ID VARCHAR(255) NOT NULL,
    UM_ACTION VARCHAR(255) NOT NULL,
    UM_TENANT_ID INTEGER DEFAULT 0,
    PRIMARY KEY (UM_ID)
);

CREATE TABLE IF NOT EXISTS UM_ORG_ROLE_USER (
    UM_USER_ID VARCHAR(255) NOT NULL,
    UM_ROLE_ID VARCHAR(255) NOT NULL,
    CONSTRAINT FK_UM_ORG_ROLE_USER_UM_ORG_ROLE FOREIGN KEY (UM_ROLE_ID) REFERENCES UM_ORG_ROLE(UM_ROLE_ID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS UM_ORG_ROLE_GROUP(
    UM_GROUP_ID VARCHAR(255) NOT NULL,
    UM_ROLE_ID VARCHAR(255) NOT NULL,
    CONSTRAINT FK_UM_ORG_ROLE_GROUP_UM_ORG_ROLE FOREIGN KEY (UM_ROLE_ID) REFERENCES UM_ORG_ROLE(UM_ROLE_ID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS UM_ORG_ROLE_PERMISSION(
    UM_PERMISSION_ID INTEGER NOT NULL,
    UM_ROLE_ID VARCHAR(255) NOT NULL,
    CONSTRAINT FK_UM_ORG_ROLE_PERMISSION_UM_ORG_ROLE FOREIGN KEY (UM_ROLE_ID) REFERENCES UM_ORG_ROLE(UM_ROLE_ID) ON DELETE CASCADE,
    CONSTRAINT FK_UM_ORG_ROLE_PERMISSION_UM_ORG_PERMISSION FOREIGN KEY (UM_PERMISSION_ID) REFERENCES UM_ORG_PERMISSION(UM_ID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS UM_ORG_HIERARCHY (
    UM_PARENT_ID VARCHAR(36) NOT NULL,
    UM_ID VARCHAR(36) NOT NULL,
    DEPTH INTEGER,
    PRIMARY KEY (UM_PARENT_ID, UM_ID),
    FOREIGN KEY (UM_PARENT_ID) REFERENCES UM_ORG(UM_ID) ON DELETE CASCADE,
    FOREIGN KEY (UM_ID) REFERENCES UM_ORG(UM_ID) ON DELETE CASCADE
);

INSERT INTO UM_ORG_HIERARCHY(UM_PARENT_ID, UM_ID, DEPTH)
SELECT UM_PARENT_ID, UM_ID, DEPTH FROM (
	SELECT
	    '10084a8d-113f-4211-a0d5-efe36b082211' AS UM_PARENT_ID,
	    '10084a8d-113f-4211-a0d5-efe36b082211' AS UM_ID,
	    0 AS DEPTH
) S
WHERE NOT EXISTS (SELECT * FROM UM_ORG_HIERARCHY OH WHERE OH.UM_PARENT_ID = S.UM_PARENT_ID AND OH.UM_ID = S.UM_ID);

-------------------------GROUP ID DOMAIN MAPPER TABLES ----------------------------

CREATE TABLE IF NOT EXISTS UM_GROUP_UUID_DOMAIN_MAPPER (
    UM_ID INTEGER NOT NULL AUTO_INCREMENT,
    UM_GROUP_ID VARCHAR(255) NOT NULL,
    UM_DOMAIN_ID INTEGER NOT NULL,
    UM_TENANT_ID INTEGER DEFAULT 0,
    PRIMARY KEY (UM_ID),
    UNIQUE (UM_GROUP_ID),
    FOREIGN KEY (UM_DOMAIN_ID, UM_TENANT_ID) REFERENCES UM_DOMAIN(UM_DOMAIN_ID, UM_TENANT_ID) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS GRP_UUID_DM_GRP_ID_TID ON UM_GROUP_UUID_DOMAIN_MAPPER(UM_GROUP_ID, UM_TENANT_ID);