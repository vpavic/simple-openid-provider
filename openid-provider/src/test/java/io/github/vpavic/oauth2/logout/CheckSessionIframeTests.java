package io.github.vpavic.oauth2.logout;

import org.junit.Before;
import org.junit.Test;
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

import io.github.vpavic.oauth2.LogoutSecurityConfiguration;
import io.github.vpavic.oauth2.OpenIdProviderWebMvcConfiguration;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link CheckSessionIframe}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebAppConfiguration
@ContextConfiguration
public class CheckSessionIframeTests {

	@Autowired
	private WebApplicationContext wac;

	private MockMvc mvc;

	@Before
	public void setUp() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.wac).apply(springSecurity()).build();
	}

	@Test
	public void getCheckSessionIframe() throws Exception {
		this.mvc.perform(get(CheckSessionIframe.PATH_MAPPING)).andExpect(status().isOk())
				.andExpect(content().string(containsString("<title>Check Session Iframe</title>")))
				.andExpect(content().string(containsString("var cookie = getCookie(\"sid\");")));
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@Import({ OpenIdProviderWebMvcConfiguration.class, LogoutSecurityConfiguration.class })
	static class Config {

		@Bean
		public CheckSessionIframe endSessionEndpoint() {
			return new CheckSessionIframe("sid");
		}

	}

}
