package de.codecentric.elasticsearch.plugin.kerberosrealm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.client.KerberizedClient;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.shield.ShieldPlugin;
import org.junit.Assert;
import org.junit.Test;

import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.net.InetAddress;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class KerberosRealmIT {

    @Test
    public void should_initially_responds_with_status_code_401() throws IOException {
        String url = System.getProperty("elasticsearch.rest.url");

        HttpClient client = HttpClients.createDefault();
        HttpGet request = new HttpGet(url);
        HttpResponse response = client.execute(request);

        Assert.assertEquals(response.getStatusLine().getStatusCode(), 401);
    }

    @Test
    public void should_authenticate_a_transport_client() throws IOException, LoginException {
        int transportPort = Integer.valueOf(System.getProperty("elasticsearch.transport.port"));

        final Settings settings = Settings.builder().put("cluster.name", "elasticsearch")
                .putArray("plugin.types", ShieldPlugin.class.getName()).build();

        try (TransportClient client = TransportClient.builder().settings(settings).build()) {
            client.addTransportAddress(new InetSocketTransportAddress(InetAddress.getByName(System.getProperty("elasticsearch.host")), transportPort));
            try (KerberizedClient kc = new KerberizedClient(client, "user@LOCALHOST", "password", "HTTP/localhost@LOCALHOST")) {

                ClusterHealthResponse response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));

                response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));

                response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));
                assertThat(response.status(), is(RestStatus.OK));
                assertThat(response.getStatus(), is(ClusterHealthStatus.GREEN));
            }
        }
    }

    @Test(expected = LoginException.class)
    public void should_not_authenticate_a_transport_client_with_the_wrong_password() throws Exception {
        int transportPort = Integer.valueOf(System.getProperty("elasticsearch.transport.port"));

        final Settings settings = Settings.builder().put("cluster.name", "elasticsearch")
                .putArray("plugin.types", ShieldPlugin.class.getName()).build();

        try (TransportClient client = TransportClient.builder().settings(settings).build()) {
            client.addTransportAddress(new InetSocketTransportAddress(InetAddress.getByName(System.getProperty("elasticsearch.host")), transportPort));
            new KerberizedClient(client, "user@LOCALHOST", "wrong_password", "HTTP/localhost@LOCALHOST");
        }
    }
}