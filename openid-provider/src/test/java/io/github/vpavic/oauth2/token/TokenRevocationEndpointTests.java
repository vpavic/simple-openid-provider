package io.github.vpavic.oauth2.token;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import io.github.vpavic.oauth2.OpenIdProviderConfiguration;
import io.github.vpavic.oauth2.client.ClientRepository;

/**
 * Tests for {@link TokenRevocationEndpoint}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebMvcTest(TokenRevocationEndpoint.class)
@Import(OpenIdProviderConfiguration.class)
public class TokenRevocationEndpointTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@MockBean
	private ClientRepository clientRepository;

	@MockBean
	private RefreshTokenStore refreshTokenStore;

	@Test
	public void test() {
		// TODO
	}

}
