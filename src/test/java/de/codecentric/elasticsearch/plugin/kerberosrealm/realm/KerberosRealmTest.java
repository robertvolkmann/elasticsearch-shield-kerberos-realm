package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.env.Environment;
import org.elasticsearch.xpack.security.authc.RealmConfig;
import org.elasticsearch.xpack.security.authc.support.UsernamePasswordToken;
import org.elasticsearch.xpack.security.user.User;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

public class KerberosRealmTest {

    private KerberosRealm kerberosRealm;
    private RolesProvider mockedRolesProvider;
    private KerberosAuthenticator mockedAuthenticator;

    @Before
    public void before() {
        RealmConfig config = new RealmConfig("test", Settings.EMPTY, Settings.EMPTY, mock(Environment.class));
        mockedRolesProvider = mock(RolesProvider.class);
        mockedAuthenticator = mock(KerberosAuthenticator.class);

        kerberosRealm = new KerberosRealm(config, mockedAuthenticator, mockedRolesProvider);
    }

    @Test
    public void should_not_support_user_lookup() {
        assertThat(kerberosRealm.userLookupSupported(), is(false));
        assertThat(kerberosRealm.lookupUser("user"), is(nullValue()));
    }

    @Test
    public void should_support_only_kerberos_tokens() {
        KerberosToken kerberosToken = new KerberosToken(new byte[0]);
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(null, null);

        assertThat(kerberosRealm.supports(kerberosToken), is(true));
        assertThat(kerberosRealm.supports(usernamePasswordToken), is(false));
    }

    @Test
    public void should_not_authenticate_invalid_kerberos_tokens() {
        KerberosToken token = new KerberosToken(new byte[0]);
        when(mockedAuthenticator.authenticate(token)).thenReturn(null);

        assertThat(kerberosRealm.authenticate(token), is(nullValue()));
    }

    @Test
    public void should_return_a_token_when_request_has_valid_authorization_header() throws IOException {
        byte[] expectedToken = new byte[]{1, 2, 3};
        ThreadContext context = new ThreadContext(Settings.EMPTY);
        context.putHeader("Authorization", "Negotiate " + DatatypeConverter.printBase64Binary(expectedToken));

        KerberosToken token = kerberosRealm.token(context);

        assertThat(token, is(notNullValue()));
        assertArrayEquals(token.credentials(), expectedToken);
    }

    @Test
    public void should_authenticate_valid_kerberos_tokens() {
        String principal = "principal";
        KerberosToken token = new KerberosToken(new byte[0]);
        when(mockedAuthenticator.authenticate(token)).thenReturn(principal);
        String[] roles = new String[]{"role 1", "role 2"};
        when(mockedRolesProvider.getRoles(principal)).thenReturn(roles);

        User user = kerberosRealm.authenticate(token);

        verify(mockedRolesProvider).getRoles(principal);
        assertThat(user.principal(), is(principal));
        assertThat(user.roles(), arrayContainingInAnyOrder(roles));
    }
}
