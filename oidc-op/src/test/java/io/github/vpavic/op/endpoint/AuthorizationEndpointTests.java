package io.github.vpavic.op.endpoint;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.token.TokenService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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

	// OAuth2 requests

	@Test
	@WithMockUser
	public void oAuth2_authCode_get_minimumParams_isOk() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();
		MockHttpSession session = new MockHttpSession();

		given(this.authorizationCodeService.create(anyMap())).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get("/authorize?response_type=code&client_id=test-client")
				.session(session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}", authorizationCode.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_authCode_post_minimumParams_isOk() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();
		MockHttpSession session = new MockHttpSession();

		given(this.authorizationCodeService.create(anyMap())).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = post("/authorize").content("response_type=code&client_id=test-client")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}", authorizationCode.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_implicitRequest_get_minimumParams_isOk() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		MockHttpSession session = new MockHttpSession();

		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());

		MockHttpServletRequestBuilder request = get("/authorize?response_type=token&client_id=test-client")
				.session(session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&token_type=Bearer", accessToken.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_implicitRequest_post_minimumParams_isOk() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		MockHttpSession session = new MockHttpSession();

		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());

		MockHttpServletRequestBuilder request = post("/authorize").content("response_type=token&client_id=test-client")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&token_type=Bearer", accessToken.getValue()));
	}

	// OIDC requests

	@Test
	@WithMockUser
	public void oidc_authCode_get_minimumParams_isOk() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();
		MockHttpSession session = new MockHttpSession();

		given(this.authorizationCodeService.create(anyMap())).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}&session_state={sessionState}",
						authorizationCode.getValue(), session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_authCode_post_minimumParams_isOk() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();
		MockHttpSession session = new MockHttpSession();

		given(this.authorizationCodeService.create(anyMap())).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = post("/authorize")
				.content("scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}&session_state={sessionState}",
						authorizationCode.getValue(), session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_implicitRequest_get_minimumParams_isOk() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		MockHttpSession session = new MockHttpSession();

		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&id_token={idToken}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), idToken.serialize(), session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_implicitRequest_post_minimumParams_isOk() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		MockHttpSession session = new MockHttpSession();

		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/authorize").content(
				"scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&id_token={idToken}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), idToken.serialize(), session.getId()));
	}

	// Misc requests

	@Test
	@WithMockUser
	public void get_noParams_isBadRequest() throws Exception {
		this.mvc.perform(get("/authorize")).andExpect(status().isBadRequest());
	}

	@Test
	@WithMockUser
	public void post_noParams_isBadRequest() throws Exception {
		this.mvc.perform(post("/authorize")).andExpect(status().isBadRequest());
	}

}
