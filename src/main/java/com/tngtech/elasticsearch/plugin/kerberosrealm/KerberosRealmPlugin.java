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
package com.tngtech.elasticsearch.plugin.kerberosrealm;

import com.tngtech.elasticsearch.plugin.kerberosrealm.realm.KerberosAuthenticationFailureHandler;
import com.tngtech.elasticsearch.plugin.kerberosrealm.realm.KerberosRealm;
import com.tngtech.elasticsearch.plugin.kerberosrealm.realm.KerberosRealmFactory;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.shield.authc.AuthenticationModule;

public class KerberosRealmPlugin extends Plugin {

    private static final String CLIENT_TYPE = "client.type";
    private final ESLogger logger = Loggers.getLogger(this.getClass());
    private final boolean client;

    public KerberosRealmPlugin(Settings settings) {
        client = !"node".equals(settings.get(CLIENT_TYPE, "node"));
        logger.info("Start Kerberos Realm Plugin (mode: {})", settings.get(CLIENT_TYPE));
    }

    @Override
    public String name() {
        return KerberosRealm.TYPE + "-realm";
    }

    @Override
    public String description() {
        return "Kerberos/SPNEGO Realm";
    }

    public void onModule(AuthenticationModule authenticationModule) {
        if (!client) {
            authenticationModule.addCustomRealm(KerberosRealm.TYPE, KerberosRealmFactory.class);
            authenticationModule.setAuthenticationFailureHandler(KerberosAuthenticationFailureHandler.class);
        } else {
            logger.warn("This plugin is not necessary for client nodes");
        }
    }
}