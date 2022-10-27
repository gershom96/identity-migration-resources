INSERT INTO IDN_OIDC_PROPERTY (TENANT_ID,CONSUMER_KEY,PROPERTY_KEY,PROPERTY_VALUE)
SELECT TENANT_ID,CONSUMER_KEY,'idTokenAudience',PROPERTY_VALUE
FROM IDN_OIDC_PROPERTY WHERE PROPERTY_KEY = 'audience';

INSERT INTO IDN_OIDC_PROPERTY (TENANT_ID,CONSUMER_KEY,PROPERTY_KEY,PROPERTY_VALUE)
SELECT TENANT_ID,CONSUMER_KEY,'accessTokenAudience',PROPERTY_VALUE
FROM IDN_OIDC_PROPERTY WHERE PROPERTY_KEY = 'audience';
