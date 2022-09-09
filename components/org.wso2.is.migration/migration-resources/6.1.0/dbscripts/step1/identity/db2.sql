INSERT INTO IDN_OIDC_PROPERTY (TENANT_ID,CONSUMER_KEY,PROPERTY_KEY,PROPERTY_VALUE)
SELECT TENANT_ID,CONSUMER_KEY,'idTokenAudience',PROPERTY_VALUE
FROM IDN_OIDC_PROPERTY WHERE PROPERTY_KEY = 'audience'
/

UPDATE IDN_OIDC_PROPERTY SET PROPERTY_KEY='accessTokenAudience' WHERE PROPERTY_KEY='audience'
/
