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

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link CheckSessionIframe}.
 */
@ExtendWith(SpringExtension.class)
@WebAppConfiguration
@ContextConfiguration
class CheckSessionIframeTests {

	@Autowired
	private WebApplicationContext wac;

	private MockMvc mvc;

	@BeforeEach
	void setUp() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
	}

	@Test
	void getCheckSessionIframe() throws Exception {
		this.mvc.perform(get(CheckSessionIframe.PATH_MAPPING)).andExpect(status().isOk())
				.andExpect(content().string(containsString("<title>Check Session Iframe</title>")))
				.andExpect(content().string(containsString("var cookie = getCookie(\"sid\");")));
	}

	@Configuration
	@EnableWebMvc
	static class Config {

		@Bean
		public CheckSessionHandler checkSessionIframeHandler() {
			return new CheckSessionHandler("sid");
		}

		@Bean
		public CheckSessionIframe checkSessionIframe() {
			return new CheckSessionIframe(checkSessionIframeHandler());
		}

	}

}
