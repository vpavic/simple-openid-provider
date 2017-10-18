package io.github.vpavic.op.oauth2.checksession;

import io.github.vpavic.op.oauth2.checksession.CheckSessionIframe;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link CheckSessionIframe}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebMvcTest(controllers = CheckSessionIframe.class, secure = false)
public class CheckSessionIframeTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@Test
	public void getCheckSessionIframeDisabled() throws Exception {
		this.mvc.perform(get("/oauth2/check-session")).andExpect(status().isNotFound());
	}

}
