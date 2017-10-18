package io.github.vpavic.op.oauth2.token;

import io.github.vpavic.op.oauth2.client.ClientRepository;
import io.github.vpavic.op.oauth2.token.RefreshTokenStore;
import io.github.vpavic.op.oauth2.token.RevocationEndpoint;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Tests for {@link RevocationEndpoint}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebMvcTest(controllers = RevocationEndpoint.class)
public class RevocationEndpointTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@MockBean
	private ClientRepository clientRepository;

	@MockBean
	private RefreshTokenStore refreshTokenStore;

	@Test
	public void test() {
		// TODO
	}

}
