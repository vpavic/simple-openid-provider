package io.github.vpavic.op.oauth2.endsession;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import io.github.vpavic.op.config.OpenIdProviderConfiguration;
import io.github.vpavic.op.oauth2.client.ClientRepository;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link EndSessionEndpoint}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebMvcTest(EndSessionEndpoint.class)
@Import(OpenIdProviderConfiguration.class)
public class EndSessionEndpointTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@MockBean
	private ClientRepository clientRepository;

	@Test
	@WithMockUser
	public void getEndSessionEndpointDisabled() throws Exception {
		this.mvc.perform(get("/oauth2/check-session")).andExpect(status().isNotFound());
	}

}
