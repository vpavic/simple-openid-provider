package io.github.vpavic.op.oauth2.jwk;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link JwkSetEndpoint}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebMvcTest(controllers = JwkSetEndpoint.class, secure = false)
public class JwkSetEndpointTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@MockBean
	private JwkSetLoader jwkSetLoader;

	@Test
	public void getKeys() throws Exception {
		given(this.jwkSetLoader.load()).willReturn(new JWKSet());

		this.mvc.perform(get("/oauth2/keys")).andExpect(status().isOk()).andExpect(jsonPath("$.keys").isEmpty());
	}

}
