package org.wso2.carbon.is.migration.service.v610.migrator;

import org.wso2.carbon.identity.core.migrate.MigrationClientException;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.is.migration.service.SchemaMigrator;

public class AudiencesMigrator extends SchemaMigrator {

    @Override
    public void migrate() throws MigrationClientException {

        if(!OAuth2Util.checkConfigLegacyAudienceStatus()){
            super.migrate();

        }
    }
}
