package io.github.vpavic.oauth2.endpoint;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import io.github.vpavic.oauth2.config.DiscoverySecurityConfiguration;
import io.github.vpavic.oauth2.config.OpenIdProviderWebMvcConfiguration;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link JwkSetEndpoint}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebAppConfiguration
@ContextConfiguration
public class JwkSetEndpointTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private WebApplicationContext wac;

	private MockMvc mvc;

	@Autowired
	private JwkSetLoader jwkSetLoader;

	@Before
	public void setUp() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.wac).apply(springSecurity()).build();
	}

	@Test
	public void getKeys() throws Exception {
		given(this.jwkSetLoader.load()).willReturn(new JWKSet());

		this.mvc.perform(get("/oauth2/keys")).andExpect(status().isOk()).andExpect(jsonPath("$.keys").isEmpty());
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@Import({ OpenIdProviderWebMvcConfiguration.class, DiscoverySecurityConfiguration.class })
	static class Config {

		@Bean
		public JwkSetLoader jwkSetLoader() {
			return mock(JwkSetLoader.class);
		}

		@Bean
		public JwkSetEndpoint jwkSetEndpoint() {
			return new JwkSetEndpoint(jwkSetLoader());
		}

	}

}
