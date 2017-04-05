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

   Author: Kerby Project, Apache Software Foundation, https://directory.apache.org/kerby/
 */
package de.codecentric.elasticsearch.plugin.kerberosrealm.realm.support;

//taken from the apache kerby project
//https://directory.apache.org/kerby/

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.nio.file.Path;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * JAAS utilities for Kerberos login.
 */
public final class JaasKrbUtil {

    static boolean ENABLE_DEBUG = false;

    private JaasKrbUtil() {
    }

    public static Subject loginUsingKeytab(final String principal, final Path keytabPath) throws LoginException {
        final Set<Principal> principals = new HashSet<>();
        principals.add(new KerberosPrincipal(principal));

        final Subject subject = new Subject(false, principals, new HashSet<>(), new HashSet<>());

        final Configuration conf = useKeytab(principal, keytabPath);
        final String confName = "KeytabConf";
        final LoginContext loginContext = new LoginContext(confName, subject, null, conf);
        loginContext.login();
        return loginContext.getSubject();
    }

    private static Configuration useKeytab(final String principal, final Path keytabPath) {
        return new KeytabJaasConf(principal, keytabPath, false);
    }

    private static String getKrb5LoginModuleName() {
        return System.getProperty("java.vendor").contains("IBM") ? "com.ibm.security.auth.module.Krb5LoginModule"
                : "com.sun.security.auth.module.Krb5LoginModule";
    }

    static class KeytabJaasConf extends Configuration {
        private final String principal;
        private final Path keytabPath;
        private final boolean initiator;

        KeytabJaasConf(final String principal, final Path keytab, final boolean initiator) {
            this.principal = principal;
            this.keytabPath = keytab;
            this.initiator = initiator;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
            final Map<String, String> options = new HashMap<>();
            options.put("keyTab", keytabPath.toAbsolutePath().toString());
            options.put("principal", principal);
            options.put("useKeyTab", "true");
            options.put("storeKey", "true");
            options.put("doNotPrompt", "true");
            options.put("renewTGT", "false");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", String.valueOf(initiator));
            options.put("debug", String.valueOf(ENABLE_DEBUG));

            return new AppConfigurationEntry[] { new AppConfigurationEntry(getKrb5LoginModuleName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };
        }
    }
}