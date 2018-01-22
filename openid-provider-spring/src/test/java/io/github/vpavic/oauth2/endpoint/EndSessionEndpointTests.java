package io.github.vpavic.oauth2.endpoint;

import com.nimbusds.oauth2.sdk.id.Issuer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import io.github.vpavic.oauth2.client.ClientRepository;

import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link EndSessionEndpoint}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebAppConfiguration
@ContextConfiguration
public class EndSessionEndpointTests {

	@Autowired
	private WebApplicationContext wac;

	private MockMvc mvc;

	@Before
	public void setUp() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
	}

	@Test
	public void getEndSessionEndpoint() throws Exception {
		this.mvc.perform(get(EndSessionEndpoint.PATH_MAPPING)).andExpect(status().isOk())
				.andExpect(forwardedUrl("/logout"));
	}

	@Configuration
	@EnableWebMvc
	static class Config {

		@Bean
		public ClientRepository clientRepository() {
			return mock(ClientRepository.class);
		}

		@Bean
		public EndSessionHandler endSessionEndpointHandler() {
			return new EndSessionHandler(new Issuer("http://example.com"), clientRepository());
		}

		@Bean
		public EndSessionEndpoint endSessionEndpoint() {
			return new EndSessionEndpoint(endSessionEndpointHandler());
		}

	}

}
