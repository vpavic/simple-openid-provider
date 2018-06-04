package io.github.vpavic.oauth2.endpoint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

/**
 * Tests for {@link TokenRevocationEndpoint}.
 */
@ExtendWith(SpringExtension.class)
@WebAppConfiguration
@ContextConfiguration
class TokenRevocationEndpointTests {

	@Autowired
	private WebApplicationContext wac;

	@Autowired
	private TokenHandler tokenHandler;

	private MockMvc mvc;

	@BeforeEach
	void setUp() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
		reset(this.tokenHandler);
	}

	// TODO add tests

	@Configuration
	@EnableWebMvc
	static class Config {

		@Bean
		public TokenHandler tokenHandler() {
			return mock(TokenHandler.class);
		}

		@Bean
		public TokenRevocationEndpoint tokenRevocationEndpoint() {
			return new TokenRevocationEndpoint(tokenHandler());
		}

	}

}
