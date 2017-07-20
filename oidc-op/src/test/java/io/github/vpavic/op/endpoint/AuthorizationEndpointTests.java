package io.github.vpavic.op.endpoint;

import java.security.Principal;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
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
import io.github.vpavic.op.token.TokenService;

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
	private TokenService tokenService;

	@Before
	public void setUp() throws Exception {
		given(this.authorizationCodeService.create(any(Tokens.class))).willReturn(new AuthorizationCode("test"));
		given(this.tokenService.createAccessToken(any(AuthenticationRequest.class), any(Principal.class)))
				.willReturn(new BearerAccessToken());
		given(this.tokenService.createRefreshToken()).willReturn(new RefreshToken());
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(Principal.class)))
				.willReturn(new PlainJWT(new JWTClaimsSet.Builder().build()));
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
