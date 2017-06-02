/*
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.support.Krb5Config;
import org.elasticsearch.xpack.security.authc.Realm;
import org.elasticsearch.xpack.security.authc.RealmConfig;

public class KerberosRealmFactory implements Realm.Factory {

    @Override
    public KerberosRealm create(RealmConfig config) {
        new Krb5Config(config).setJavaProperty();
        return new KerberosRealm(config, new KerberosAuthenticator(config), new RolesProvider(config));
    }
}
