package io.github.vpavic.oauth2.checksession;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link CheckSessionIframe}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebMvcTest(CheckSessionIframe.class)
@Import(CheckSessionConfiguration.SecurityConfiguration.class)
public class CheckSessionIframeTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@Test
	public void getCheckSessionIframeDisabled() throws Exception {
		this.mvc.perform(get("/oauth2/check-session")).andExpect(status().isOk())
				.andExpect(content().string(containsString("<title>OIDC Provider</title>")));
	}

}
