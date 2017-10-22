package io.github.vpavic.oauth2.client;

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

/**
 * Tests for {@link ClientConfigurationEndpoint}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebMvcTest(ClientConfigurationEndpoint.class)
@Import(OpenIdProviderConfiguration.class)
public class ClientConfigurationEndpointTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@MockBean
	private ClientRepository clientRepository;

	@MockBean
	private ClientService clientService;

	@Test
	public void test() {
		// TODO
	}

}
