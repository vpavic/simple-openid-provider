package io.github.vpavic.op.endpoint;

import java.net.URI;
import java.util.Collections;
import java.util.Date;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.junit.Before;
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

import io.github.vpavic.op.client.ClientRepository;
import io.github.vpavic.op.code.AuthorizationCodeContext;
import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.token.TokenService;

import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link AuthorizationEndpoint}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebMvcTest(AuthorizationEndpoint.class)
public class AuthorizationEndpointTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@MockBean
	private ClientRepository clientRepository;

	@MockBean
	private AuthorizationCodeService authorizationCodeService;

	@MockBean
	private TokenService tokenService;

	private MockHttpSession session;

	@Before
	public void setUp() {
		this.session = new MockHttpSession();
	}

	// OAuth2 requests

	@Test
	@WithMockUser
	public void oAuth2_authCode_minimumParams_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestAuthCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=code&client_id=test-client&redirect_uri=http://example.com&scope=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}", authorizationCode.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_authCode_minimumParamsWithPost_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestAuthCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = post("/authorize")
				.content("response_type=code&client_id=test-client&redirect_uri=http://example.com&scope=test")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}", authorizationCode.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_authCode_withState_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();
		State state = new State();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestAuthCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=code&client_id=test-client&redirect_uri=http://example.com&scope=test&state="
						+ state).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com?code={code}&state={state}", authorizationCode.getValue(), state.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_authCode_withoutClientId_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestAuthCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=code&redirect_uri=http://example.com&scope=test").session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void oAuth2_authCode_withoutRedirectUri_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestAuthCodeClient());

		MockHttpServletRequestBuilder request = get("/authorize?response_type=code&client_id=test-client&scope=test")
				.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void oAuth2_authCode_withInvalidRedirectUri_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestAuthCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=code&client_id=test-client&redirect_uri=http://invalid.example.com&scope=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void oAuth2_authCode_withoutScope_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestAuthCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("http://example.com?error_description=*&error=" + error.getCode()));
	}

	@Test
	@WithMockUser
	public void oAuth2_authCode_withoutScopeWithInvalidRedirectUri_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestAuthCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=code&client_id=test-client&redirect_uri=http://invalid.example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void oAuth2_implicit_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestImplicitClient());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=token&client_id=test-client&redirect_uri=http://example.com&scope=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&token_type=Bearer", accessToken.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_implicit_minimumParamsWithPost_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestImplicitClient());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);

		MockHttpServletRequestBuilder request = post("/authorize")
				.content("response_type=token&client_id=test-client&redirect_uri=http://example.com&scope=test")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&token_type=Bearer", accessToken.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_implicit_withState_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		State state = new State();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestImplicitClient());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=token&client_id=test-client&redirect_uri=http://example.com&scope=test&state="
						+ state.getValue()).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(
				redirectedUrl("http://example.com#access_token={accessToken}&state={state}&token_type=Bearer",
						accessToken.getValue(), state.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_implicit_withoutClientId_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestImplicitClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=token&redirect_uri=http://example.com&scope=test").session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void oAuth2_implicit_withoutRedirectUri_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestImplicitClient());

		MockHttpServletRequestBuilder request = get("/authorize#response_type=token&client_id=test-client&scope=test")
				.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void oAuth2_implicit_withoutScope_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestImplicitClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=token&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("http://example.com#error_description=*&error=" + error.getCode()));
	}

	@Test
	@WithMockUser
	public void oAuth2_hybrid_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestHybridClient());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=code token&client_id=test-client&redirect_uri=http://example.com&scope=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com#access_token={accessToken}&code={code}&token_type=Bearer",
						accessToken.getValue(), authorizationCode.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_hybrid_minimumParamsWithPost_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestHybridClient());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = post("/authorize")
				.content("response_type=code token&client_id=test-client&redirect_uri=http://example.com&scope=test")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com#access_token={accessToken}&code={code}&token_type=Bearer",
						accessToken.getValue(), authorizationCode.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_hybrid_withState_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		AuthorizationCode authorizationCode = new AuthorizationCode();
		State state = new State();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestHybridClient());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=code token&client_id=test-client&redirect_uri=http://example.com&scope=test&state="
						+ state.getValue()).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl(
						"http://example.com#access_token={accessToken}&code={code}&state={state}&token_type=Bearer",
						accessToken.getValue(), authorizationCode.getValue(), state.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_hybrid_withoutClientId_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestHybridClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=code token&redirect_uri=http://example.com&scope=test").session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void oAuth2_hybrid_withoutRedirectUri_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestHybridClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize#response_type=code token&client_id=test-client&scope=test").session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void oAuth2_hybrid_withoutScope_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestHybridClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=code token&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("http://example.com#error_description=*&error=" + error.getCode()));
	}

	@Test
	@WithMockUser
	public void oAuth2_invalid_withoutResponseType_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oAuth2TestHybridClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?client_id=test-client&redirect_uri=http://example.com&scope=test").session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("http://example.com?error_description=*&error=" + error.getCode()));
	}

	// OIDC requests

	@Test
	@WithMockUser
	public void oidc_authCode_minimumParams_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oidcTestAuthCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}&session_state={sessionState}",
						authorizationCode.getValue(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_authCode_minimumParamsWithPost_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oidcTestAuthCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = post("/authorize")
				.content("scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}&session_state={sessionState}",
						authorizationCode.getValue(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_authCode_withState_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();
		State state = new State();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oidcTestAuthCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com&state="
						+ state.getValue()).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}&state={state}&session_state={sessionState}",
						authorizationCode.getValue(), state.getValue(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_authCode_withoutOpenIdScope_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oidcTestAuthCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("http://example.com?error_description=*&error=" + error.getCode()));
	}

	@Test
	@WithMockUser
	public void oidc_authCode_withoutClientId_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oidcTestAuthCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code&redirect_uri=http://example.com").session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void oidc_authCode_withoutRedirectUri_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oidcTestAuthCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code&client_id=test-client&state=").session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void oidc_implicitWithIdTokenAndToken_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(oidcTestImplicitWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&id_token={idToken}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), idToken.serialize(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_implicitWithIdTokenAndToken_minimumParamsWithPost_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(oidcTestImplicitWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/authorize").content(
				"scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&id_token={idToken}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), idToken.serialize(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_implicitWithIdToken_minimumParams_isSuccess() throws Exception {
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(oidcTestImplicitWithIdTokenClient());
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=id_token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com#id_token={idToken}&session_state={sessionState}",
						idToken.serialize(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_implicitWithIdTokenAndToken_withState_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		State state = new State();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(oidcTestImplicitWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test&state="
						+ state.getValue()).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&id_token={idToken}&state={state}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), idToken.serialize(), state.getValue(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_implicitWithIdTokenAndToken_withoutOpenIdScope_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(oidcTestImplicitWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("http://example.com?error_description=*&error=" + error.getCode()));
	}

	@Test
	@WithMockUser
	public void oidc_implicitWithIdTokenAndToken_withoutClientId_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(oidcTestImplicitWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=id_token token&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void oidc_implicitWithIdTokenAndToken_withoutRedirectUri_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(oidcTestImplicitWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=id_token token&client_id=test-client&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void oidc_implicitWithIdTokenAndToken_withoutNonce_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(oidcTestImplicitWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("http://example.com#error_description=*&error=" + error.getCode()));
	}

	@Test
	@WithMockUser
	public void oidc_hybridWithIdTokenAndToken_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(oidcTestHybridWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&code={code}&id_token={idToken}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), authorizationCode.getValue(), idToken.serialize(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_hybridWithIdTokenAndToken_minimumParamsWithPost_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(oidcTestHybridWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = post("/authorize").content(
				"scope=openid&response_type=code id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&code={code}&id_token={idToken}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), authorizationCode.getValue(), idToken.serialize(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_hybridWithIdToken_minimumParams_isSuccess() throws Exception {
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oidcTestHybridWithIdTokenClient());
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code id_token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(
				redirectedUrl("http://example.com#code={code}&id_token={idToken}&session_state={sessionState}",
						authorizationCode.getValue(), idToken.serialize(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_hybridWithToken_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(oidcTestHybridWithTokenClient());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&code={code}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), authorizationCode.getValue(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_hybridWithIdTokenAndToken_withState_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();
		State state = new State();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(oidcTestHybridWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test&state="
						+ state.getValue()).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&code={code}&id_token={idToken}&state={state}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), authorizationCode.getValue(), idToken.serialize(), state.getValue(),
				this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_hybridWithIdTokenAndToken_withoutClientId_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(oidcTestHybridWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code id_token token&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void oidc_hybridWithIdTokenAndToken_withoutRedirectUri_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(oidcTestHybridWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code id_token token&client_id=test-client&state=")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	private static OIDCClientInformation testClient(ResponseType responseType, Scope scope) {
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.applyDefaults();
		clientMetadata.setRedirectionURI(URI.create("http://example.com"));
		clientMetadata.setScope(scope);
		clientMetadata.setResponseTypes(Collections.singleton(responseType));

		return new OIDCClientInformation(new ClientID("test-client"), new Date(), clientMetadata,
				new Secret("test-secret"));
	}

	private static OIDCClientInformation oAuth2TestAuthCodeClient() {
		return testClient(new ResponseType(ResponseType.Value.CODE), new Scope("test"));
	}

	private static OIDCClientInformation oAuth2TestImplicitClient() {
		return testClient(new ResponseType(ResponseType.Value.TOKEN), new Scope("test"));
	}

	private static OIDCClientInformation oAuth2TestHybridClient() {
		return testClient(new ResponseType(ResponseType.Value.CODE, ResponseType.Value.TOKEN), new Scope("test"));
	}

	private static OIDCClientInformation oidcTestAuthCodeClient() {
		return testClient(new ResponseType(ResponseType.Value.CODE), new Scope(OIDCScopeValue.OPENID));
	}

	private static OIDCClientInformation oidcTestImplicitWithIdTokenAndTokenClient() {
		return testClient(new ResponseType(OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN),
				new Scope(OIDCScopeValue.OPENID));
	}

	private static OIDCClientInformation oidcTestImplicitWithIdTokenClient() {
		return testClient(new ResponseType(OIDCResponseTypeValue.ID_TOKEN), new Scope(OIDCScopeValue.OPENID));
	}

	private static OIDCClientInformation oidcTestHybridWithIdTokenAndTokenClient() {
		return testClient(
				new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN),
				new Scope(OIDCScopeValue.OPENID));
	}

	private static OIDCClientInformation oidcTestHybridWithIdTokenClient() {
		return testClient(new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN),
				new Scope(OIDCScopeValue.OPENID));
	}

	private static OIDCClientInformation oidcTestHybridWithTokenClient() {
		return testClient(new ResponseType(ResponseType.Value.CODE, ResponseType.Value.TOKEN),
				new Scope(OIDCScopeValue.OPENID));
	}

}
