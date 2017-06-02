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
           and Apache Tomcat project https://tomcat.apache.org/ (see comments and NOTICE)
 */
package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.realm.KerberosToken.KerberosTokenFactory;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.xpack.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.security.authc.Realm;
import org.elasticsearch.xpack.security.authc.RealmConfig;
import org.elasticsearch.xpack.security.user.User;

import java.util.Arrays;

public class KerberosRealm extends Realm {

    public static final String WWW_AUTHENTICATE_HEADER = "WWW-Authenticate";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String TYPE = "kerberos";

    private final RolesProvider rolesProvider;
    private final KerberosAuthenticator kerberosAuthenticator;

    public KerberosRealm(RealmConfig config, KerberosAuthenticator kerberosAuthenticator, RolesProvider rolesProvider) {
        super(TYPE, config);
        this.rolesProvider = rolesProvider;
        this.kerberosAuthenticator = kerberosAuthenticator;
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof KerberosToken;
    }

    @Override
    public KerberosToken token(ThreadContext threadContext) {
        String authorizationHeader = threadContext.getHeader(AUTHORIZATION_HEADER);
        logger.debug("Authorization header: {}", authorizationHeader);

        return new KerberosTokenFactory().extractToken(authorizationHeader);
    }

    @Override
    public User authenticate(AuthenticationToken token) {
        String actualUser = kerberosAuthenticator.authenticate((KerberosToken) token);

        if (actualUser == null) {
            logger.warn("User cannot be authenticated");
            return null;
        }

        String[] userRoles = rolesProvider.getRoles(actualUser);

        logger.debug("User '{}' with roles {} successully authenticated", actualUser, Arrays.toString(userRoles));
        return new User(actualUser, userRoles);
    }

    @Override
    public User lookupUser(String username) {
        return null;
    }

    @Override
    public boolean userLookupSupported() {
        return false;
    }
}
