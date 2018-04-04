package io.github.vpavic.oauth2.endpoint;

import com.nimbusds.jose.jwk.JWKSet;
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

import io.github.vpavic.oauth2.jwk.JwkSetLoader;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link JwkSetEndpoint}.
 */
@RunWith(SpringRunner.class)
@WebAppConfiguration
@ContextConfiguration
public class JwkSetEndpointTests {

	@Autowired
	private WebApplicationContext wac;

	private MockMvc mvc;

	@Autowired
	private JwkSetLoader jwkSetLoader;

	@Before
	public void setUp() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.wac).build();

		reset(this.jwkSetLoader);
	}

	@Test
	public void getKeys() throws Exception {
		given(this.jwkSetLoader.load()).willReturn(new JWKSet());

		this.mvc.perform(get("/oauth2/keys")).andExpect(status().isOk()).andExpect(jsonPath("$.keys").isEmpty());
	}

	@Configuration
	@EnableWebMvc
	static class Config {

		@Bean
		public JwkSetLoader jwkSetLoader() {
			return mock(JwkSetLoader.class);
		}

		@Bean
		public JwkSetHandler jwkSetEndpointHandler() {
			return new JwkSetHandler(jwkSetLoader());
		}

		@Bean
		public JwkSetEndpoint jwkSetEndpoint() {
			return new JwkSetEndpoint(jwkSetEndpointHandler());
		}

	}

}
