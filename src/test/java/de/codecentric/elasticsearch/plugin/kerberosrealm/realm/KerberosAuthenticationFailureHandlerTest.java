package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.test.rest.FakeRestRequest;
import org.elasticsearch.transport.TransportMessage;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.junit.Assert.assertThat;

public class KerberosAuthenticationFailureHandlerTest {

    private static final String NEGOTIATE = "Negotiate";
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    private KerberosAuthenticationFailureHandler failureHandler;

    @Before
    public void before() {
        failureHandler = new KerberosAuthenticationFailureHandler();
    }

    @Test
    public void should_add_www_authenticate_header_after_unsuccessful_authentication_of_rest_request() {
        KerberosToken token = new KerberosToken(new byte[0]);
        RestRequest request = new FakeRestRequest();
        ThreadContext context = new ThreadContext(Settings.EMPTY);

        ElasticsearchSecurityException securityException = failureHandler.failedAuthentication(request, token, context);

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }

    @Test
    public void should_add_www_authenticate_header_after_unsuccessful_authentication_of_transport_message() {
        KerberosToken token = new KerberosToken(new byte[0]);
        TransportMessage message = new ClusterHealthRequest();
        ThreadContext context = new ThreadContext(Settings.EMPTY);

        ElasticsearchSecurityException securityException = failureHandler.failedAuthentication(message, token, "action", context);

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }

    @Test
    public void should_add_www_authenticate_header_when_exception_occures_in_processing_a_rest_request() {
        RestRequest request = new FakeRestRequest();
        Exception exception = new Exception();
        ThreadContext context = new ThreadContext(Settings.EMPTY);

        ElasticsearchSecurityException securityException = failureHandler.exceptionProcessingRequest(request, exception, context);

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }

    @Test
    public void should_add_existing_out_token_when_elasticsearch_exception_occures_in_processing_a_rest_request() {
        RestRequest request = new FakeRestRequest();
        ElasticsearchException elasticsearchException = new ElasticsearchException("msg", "args");
        elasticsearchException.addHeader("kerberos_out_token", "outToken");
        ThreadContext context = new ThreadContext(Settings.EMPTY);

        ElasticsearchSecurityException securityException = failureHandler.exceptionProcessingRequest(request, elasticsearchException, context);

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE + " outToken"));
    }

    @Test
    public void should_only_add_www_authenticate_header_when_elasticsearch_exception_has_no_kerberos_out_token() {
        RestRequest request = new FakeRestRequest();
        ElasticsearchException elasticsearchException = new ElasticsearchException("msg", "args");
        ThreadContext context = new ThreadContext(Settings.EMPTY);

        ElasticsearchSecurityException securityException = failureHandler.exceptionProcessingRequest(request, elasticsearchException, context);

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }

    @Test
    public void should_add_www_authenticate_header_when_elasticsearch_exception_occures_in_processing_a_transport_message() {
        TransportMessage message = new ClusterHealthRequest();
        ElasticsearchException elasticsearchException = new ElasticsearchException("msg", "args");
        elasticsearchException.addHeader("kerberos_out_token", "token");
        ThreadContext context = new ThreadContext(Settings.EMPTY);

        ElasticsearchSecurityException securityException = failureHandler.exceptionProcessingRequest(message, "action", elasticsearchException, context);

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE + " token"));
    }

    @Test
    public void should_add_www_authenticate_header_when_token_is_missing_in_rest_request() {
        RestRequest request = new FakeRestRequest();
        ThreadContext context = new ThreadContext(Settings.EMPTY);

        ElasticsearchSecurityException securityException = failureHandler.missingToken(request, context);

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }

    @Test
    public void should_add_www_authenticate_header_when_token_is_missing_in_transport_message() {
        TransportMessage message = new ClusterHealthRequest();
        ThreadContext context = new ThreadContext(Settings.EMPTY);

        ElasticsearchSecurityException securityException = failureHandler.missingToken(message, "action", context);

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }

    @Test
    public void should_add_www_authenticate_header_when_authentication_is_required() {
        ThreadContext context = new ThreadContext(Settings.EMPTY);
        ElasticsearchSecurityException securityException = failureHandler.authenticationRequired("some action", context);

        assertThat(securityException.getHeader(WWW_AUTHENTICATE), hasItem(NEGOTIATE));
    }
}
