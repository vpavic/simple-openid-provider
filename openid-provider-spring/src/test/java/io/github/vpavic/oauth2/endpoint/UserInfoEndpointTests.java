package io.github.vpavic.oauth2.endpoint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

import io.github.vpavic.oauth2.claim.ClaimSource;
import io.github.vpavic.oauth2.token.AccessTokenService;

import static org.mockito.Mockito.mock;

/**
 * Tests for {@link UserInfoEndpoint}.
 */
@ExtendWith(SpringExtension.class)
@WebAppConfiguration
@ContextConfiguration
public class UserInfoEndpointTests {

	@Autowired
	private WebApplicationContext wac;

	private MockMvc mvc;

	@BeforeEach
	public void setUp() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
	}

	@Test
	public void test() {
		// TODO
	}

	@Configuration
	@EnableWebMvc
	static class Config {

		@Bean
		public UserInfoHandler userInfoEndpointHandler() {
			return new UserInfoHandler(mock(AccessTokenService.class), mock(ClaimSource.class));
		}

		@Bean
		public UserInfoEndpoint userInfoEndpoint() {
			return new UserInfoEndpoint(userInfoEndpointHandler());
		}

	}

}
