package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.utils.TemporaryFilesRule;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.shield.authc.RealmConfig;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class KerberosAuthenticatorTests {

    @Rule
    public TemporaryFilesRule temporaryFilesRule = new TemporaryFilesRule();

    @Rule
    public ExpectedException expectedExcpetion = ExpectedException.none();

    private Settings globalSettings;

    @Before
    public void before() {
        globalSettings = Settings.builder().put("path.home", temporaryFilesRule.getRoot()).build();
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_principal_is_missing() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("Unconfigured (but required) property: acceptor_principal");

        Settings realmSettings = Settings.builder()
                .put("acceptor_keytab_path", "")
                .build();
        new KerberosAuthenticator(new RealmConfig("test", realmSettings, globalSettings));
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_keytab_path_is_missing() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("Unconfigured (but required) property: acceptor_keytab_path");

        Settings realmSettings = Settings.builder()
                .put("acceptor_principal", "")
                .build();
        new KerberosAuthenticator(new RealmConfig("test", realmSettings, globalSettings));
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_keytab_is_not_readable() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("File not found or not readable");

        Settings realmSettings = Settings.builder()
                .put("acceptor_keytab_path", "")
                .put("acceptor_principal", "")
                .build();
        new KerberosAuthenticator(new RealmConfig("test", realmSettings, globalSettings));
    }

    @Test
    public void should_throw_elasticsearch_exception_when_acceptor_keytab_is_a_directory() {
        expectedExcpetion.expect(ElasticsearchException.class);
        expectedExcpetion.expectMessage("File not found or not readable");

        Settings realmSettings = Settings.builder()
                .put("acceptor_keytab_path", temporaryFilesRule.getRoot().toAbsolutePath())
                .put("acceptor_principal", "")
                .build();
        new KerberosAuthenticator(new RealmConfig("test", realmSettings, globalSettings));
    }
}
