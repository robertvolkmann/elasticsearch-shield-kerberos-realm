package de.codecentric.elasticsearch.plugin.kerberosrealm;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class KerberosRealmExtensionTest {

    @Test
    public void should_return_its_name() {
        KerberosRealmExtension realmPlugin = new KerberosRealmExtension();

        assertThat(realmPlugin.name(), is("kerberos-realm"));
    }

    @Test
    public void should_return_its_description() {
        KerberosRealmExtension realmPlugin = new KerberosRealmExtension();

        assertThat(realmPlugin.description(), is("Kerberos/SPNEGO Realm"));
    }
}
