package io.github.vpavic.op.endpoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.key.KeyService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest(AuthorizationEndpoint.class)
public class AuthorizationEndpointTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@MockBean
	private AuthorizationCodeService authorizationCodeService;

	@MockBean
	private KeyService keyService;

	@Before
	public void setUp() throws Exception {
		given(this.authorizationCodeService.create(any(Tokens.class))).willReturn(new AuthorizationCode("test"));
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
		keyGenerator.initialize(512);
		KeyPair keyPair = keyGenerator.genKeyPair();
		given(this.keyService.findDefault()).willReturn(
				new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()).privateKey(keyPair.getPrivate()).build());
	}

	@Test
	@WithMockUser
	public void authenticationRequest_withGetAndMinimumParams_isOk() throws Exception {
		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(
				redirectedUrl("http://example.com?code={code}&session_state={sessionState}", "test", session.getId()));
	}

	@Test
	@WithMockUser
	public void authenticationRequest_withPostAndMinimumParams_isOk() throws Exception {
		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(
				redirectedUrl("http://example.com?code={code}&session_state={sessionState}", "test", session.getId()));
	}

	@Test
	@WithMockUser
	public void authenticationRequest_withNoParams_isBadRequest() throws Exception {
		this.mvc.perform(get("/authorize")).andExpect(status().isBadRequest());
	}

}
