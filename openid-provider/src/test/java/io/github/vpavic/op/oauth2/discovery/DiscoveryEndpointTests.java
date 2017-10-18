package io.github.vpavic.op.oauth2.discovery;

import io.github.vpavic.op.oauth2.discovery.DiscoveryEndpoint;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link DiscoveryEndpoint}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebMvcTest(controllers = DiscoveryEndpoint.class, secure = false)
public class DiscoveryEndpointTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@Test
	public void getProviderMetadata() throws Exception {
		this.mvc.perform(get("/.well-known/openid-configuration")).andExpect(status().isOk())
				.andExpect(jsonPath("$.issuer").isString());
	}

}
