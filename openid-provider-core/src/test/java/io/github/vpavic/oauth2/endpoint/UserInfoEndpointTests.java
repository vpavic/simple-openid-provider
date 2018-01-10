package io.github.vpavic.oauth2.endpoint;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import io.github.vpavic.oauth2.authentication.AccessTokenClaimsResolver;
import io.github.vpavic.oauth2.claim.ClaimSource;
import io.github.vpavic.oauth2.config.OpenIdProviderWebMvcConfiguration;

import static org.mockito.Mockito.mock;

/**
 * Tests for {@link UserInfoEndpoint}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebAppConfiguration
@ContextConfiguration
public class UserInfoEndpointTests {

	@Autowired
	private WebApplicationContext wac;

	private MockMvc mvc;

	@Before
	public void setUp() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
	}

	@Test
	public void test() {
		// TODO
	}

	@Configuration
	@EnableWebMvc
	@Import(OpenIdProviderWebMvcConfiguration.class)
	static class Config {

		@Bean
		public UserInfoEndpoint userInfoEndpoint() {
			return new UserInfoEndpoint(mock(AccessTokenClaimsResolver.class), mock(ClaimSource.class));
		}

	}

}
