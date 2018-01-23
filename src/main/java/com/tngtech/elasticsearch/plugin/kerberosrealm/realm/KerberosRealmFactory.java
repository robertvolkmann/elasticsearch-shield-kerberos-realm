/*
   Copyright 2015 codecentric AG

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   Author: Hendrik Saly <hendrik.saly@codecentric.de>
 */
package com.tngtech.elasticsearch.plugin.kerberosrealm.realm;

import com.tngtech.elasticsearch.plugin.kerberosrealm.realm.support.PropertyUtil;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.shield.ShieldSettingsFilter;
import org.elasticsearch.shield.authc.Realm;
import org.elasticsearch.shield.authc.RealmConfig;

public class KerberosRealmFactory extends Realm.Factory<KerberosRealm> {

    private final ShieldSettingsFilter settingsFilter;

    @Inject
    public KerberosRealmFactory(final ShieldSettingsFilter settingsFilter) {
        super(KerberosRealm.TYPE, false);
        this.settingsFilter = settingsFilter;
    }

    @Override
    public KerberosRealm create(final RealmConfig config) {
        settingsFilter.filterOut("shield.authc.realms." + config.name() + ".*");
        new PropertyUtil(config).initKerberosProperty();

        RolesProvider rolesProvider = createRolesProvider(config);
        rolesProvider.setConfig(config);

        return new KerberosRealm(config, new KerberosAuthenticator(config), rolesProvider);
    }

    private RolesProvider createRolesProvider(final RealmConfig config) {
        ESLogger logger = config.logger(KerberosRealmFactory.class);
        String className = config.settings().get("rolesProvider", null);

        try {
            if (className != null && !className.isEmpty()) {
                return (RolesProvider) Class.forName(className).newInstance();
            }
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            logger.warn("Create new instance of class {} failed due to {}.", e, className, e.toString());
        }
        return new DefaultRolesProvider();
    }

    @Override
    public KerberosRealm createDefault(final String name) {
        return null;
    }
}