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
package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.transport.TransportMessage;
import org.elasticsearch.xpack.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.security.authc.DefaultAuthenticationFailureHandler;

public class KerberosAuthenticationFailureHandler extends DefaultAuthenticationFailureHandler {

    private static final String NEGOTIATE = "Negotiate";
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    private String getOutTokenFromElasticsearchException(Exception exception) {
        if (exception instanceof ElasticsearchException) {
            ElasticsearchException elasticsearchException = (ElasticsearchException) exception;
            if (elasticsearchException.getHeader("kerberos_out_token") != null) {
                return " " + elasticsearchException.getHeader("kerberos_out_token").get(0);
            }
        }
        return "";
    }

    @Override
    public ElasticsearchSecurityException failedAuthentication(RestRequest request, AuthenticationToken token, ThreadContext context) {
        ElasticsearchSecurityException securityException = super.failedAuthentication(request, token, context);
        securityException.addHeader(WWW_AUTHENTICATE, NEGOTIATE);
        return securityException;
    }

    @Override
    public ElasticsearchSecurityException failedAuthentication(TransportMessage message, AuthenticationToken token, String action, ThreadContext context) {
        ElasticsearchSecurityException securityException = super.failedAuthentication(message, token, action, context);
        securityException.addHeader(WWW_AUTHENTICATE, NEGOTIATE);
        return securityException;
    }

    @Override
    public ElasticsearchSecurityException missingToken(RestRequest request, ThreadContext context) {
        ElasticsearchSecurityException securityException = super.missingToken(request, context);
        securityException.addHeader(WWW_AUTHENTICATE, NEGOTIATE);
        return securityException;
    }

    @Override
    public ElasticsearchSecurityException missingToken(TransportMessage message, String action, ThreadContext context) {
        ElasticsearchSecurityException securityException = super.missingToken(message, action, context);
        securityException.addHeader(WWW_AUTHENTICATE, NEGOTIATE);
        return securityException;
    }

    @Override
    public ElasticsearchSecurityException exceptionProcessingRequest(RestRequest request, Exception exception, ThreadContext context) {
        ElasticsearchSecurityException securityException = super.exceptionProcessingRequest(request, exception, context);
        securityException.addHeader(WWW_AUTHENTICATE, NEGOTIATE + this.getOutTokenFromElasticsearchException(exception));
        return securityException;
    }

    @Override
    public ElasticsearchSecurityException exceptionProcessingRequest(TransportMessage message, String action, Exception exception, ThreadContext context) {
        ElasticsearchSecurityException securityException = super.exceptionProcessingRequest(message, action, exception, context);
        securityException.addHeader(WWW_AUTHENTICATE, NEGOTIATE + this.getOutTokenFromElasticsearchException(exception));
        return securityException;
    }

    @Override
    public ElasticsearchSecurityException authenticationRequired(String action, ThreadContext context) {
        ElasticsearchSecurityException securityException = super.authenticationRequired(action, context);
        securityException.addHeader(WWW_AUTHENTICATE, NEGOTIATE);
        return securityException;
    }
}
