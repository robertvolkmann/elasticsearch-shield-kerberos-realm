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
package de.codecentric.elasticsearch.plugin.kerberosrealm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosAuthenticationFailureHandler;
import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosRealm;
import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosRealmFactory;
import org.elasticsearch.common.collect.MapBuilder;
import org.elasticsearch.xpack.extensions.XPackExtension;
import org.elasticsearch.xpack.security.authc.AuthenticationFailureHandler;
import org.elasticsearch.xpack.security.authc.Realm.Factory;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

public class KerberosRealmExtension extends XPackExtension {

    @Override
    public String name() {
        return KerberosRealm.TYPE + "-realm";
    }

    @Override
    public String description() {
        return "Kerberos/SPNEGO Realm";
    }

    @Override
    public Collection<String> getRestHeaders() {
        return Arrays.asList(KerberosRealm.AUTHORIZATION_HEADER, KerberosRealm.WWW_AUTHENTICATE_HEADER);
    }

    @Override
    public Map<String, Factory> getRealms() {
        return new MapBuilder<String, Factory>()
                .put(KerberosRealm.TYPE, new KerberosRealmFactory())
                .immutableMap();
    }

    @Override
    public AuthenticationFailureHandler getAuthenticationFailureHandler() {
        return new KerberosAuthenticationFailureHandler();
    }
}
