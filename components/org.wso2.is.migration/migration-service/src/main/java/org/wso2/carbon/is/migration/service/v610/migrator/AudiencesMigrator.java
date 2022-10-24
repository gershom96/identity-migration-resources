/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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
