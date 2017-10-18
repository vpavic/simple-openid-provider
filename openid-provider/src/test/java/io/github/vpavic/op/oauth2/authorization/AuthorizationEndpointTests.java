package io.github.vpavic.op.oauth2.authorization;

import java.net.URI;
import java.util.Collections;
import java.util.Date;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.junit.Before;
import org.junit.Ignore;
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

import io.github.vpavic.op.oauth2.client.ClientRepository;
import io.github.vpavic.op.oauth2.code.AuthorizationCodeContext;
import io.github.vpavic.op.oauth2.code.AuthorizationCodeService;
import io.github.vpavic.op.oauth2.token.AccessTokenClaimsMapper;
import io.github.vpavic.op.oauth2.token.AccessTokenRequest;
import io.github.vpavic.op.oauth2.token.IdTokenClaimsMapper;
import io.github.vpavic.op.oauth2.token.IdTokenRequest;
import io.github.vpavic.op.oauth2.token.TokenService;
import io.github.vpavic.op.oauth2.userinfo.UserInfoMapper;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlTemplate;
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

	@MockBean
	private AccessTokenClaimsMapper accessTokenClaimsMapper;

	@MockBean
	private IdTokenClaimsMapper idTokenClaimsMapper;

	@MockBean
	private UserInfoMapper userInfoMapper;

	private MockHttpSession session;

	@Before
	public void setUp() {
		this.session = new MockHttpSession();
	}

	@Test
	@WithMockUser
	public void authCode_minimumParams_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlTemplate("http://example.com?code={code}", authorizationCode.getValue()));
	}

	@Test
	@WithMockUser
	public void authCode_withState_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();
		State state = new State();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com&state="
						+ state.getValue()).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrlTemplate(
				"http://example.com?code={code}&state={state}", authorizationCode.getValue(), state.getValue()));
	}

	@Test
	@WithMockUser
	public void authCode_withPromptLogin_isRequireLogin() throws Exception {
		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com&prompt=login")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl("/login"));
	}

	@Test
	@WithMockUser
	public void authCode_withPromptNoneAndAuthentication_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com&prompt=none")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlTemplate("http://example.com?code={code}", authorizationCode.getValue()));
	}

	@Test
	@Ignore // TODO this should pass without authentication
	public void authCode_withPromptNoneAndNoAuthentication_isError() throws Exception {
		ErrorObject error = OIDCError.LOGIN_REQUIRED;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com&prompt=none")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("http://example.com?error_description=*&error=" + error.getCode()));
	}

	@Test
	@WithMockUser
	public void authCode_withValidMaxAge_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com&max_age=60")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlTemplate("http://example.com?code={code}", authorizationCode.getValue()));
	}

	@Test
	@WithMockUser
	public void authCode_withExpiredMaxAge_isRequireLogin() throws Exception {
		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		Thread.sleep(1000);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com&max_age=1")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl("/login"));
	}

	@Test
	@WithMockUser
	public void authCode_withoutScope_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("http://example.com?error_description=*&error=" + error.getCode()));
	}

	@Test
	@WithMockUser
	public void authCode_withoutScopeWithInvalidRedirectUri_isError() throws Exception {
		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://invalid.example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest());
	}

	@Test
	@WithMockUser
	public void authCode_withInvalidScope_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=test&response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("http://example.com?error_description=*&error=" + error.getCode()));
	}

	@Test
	@WithMockUser
	public void authCode_withoutClientId_isError() throws Exception {
		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest());
	}

	@Test
	@WithMockUser
	public void authCode_withoutRedirectUri_isError() throws Exception {
		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code&client_id=test-client").session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest());
	}

	@Test
	@WithMockUser
	public void authCode_withInvalidRedirectUri_isError() throws Exception {
		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://invalid.example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest());
	}

	@Test
	@WithMockUser
	public void implicitWithIdTokenAndToken_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(implicitWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlTemplate(
						"http://example.com#access_token={accessToken}&id_token={idToken}&token_type=Bearer",
						accessToken.getValue(), idToken.serialize()));
	}

	@Test
	@WithMockUser
	public void implicitWithIdToken_minimumParams_isSuccess() throws Exception {
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(implicitWithIdTokenClient());
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=id_token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlTemplate("http://example.com#id_token={idToken}", idToken.serialize()));
	}

	@Test
	@WithMockUser
	public void implicitWithIdTokenAndToken_withState_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		State state = new State();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(implicitWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test&state="
						+ state.getValue()).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrlTemplate(
				"http://example.com#access_token={accessToken}&id_token={idToken}&state={state}&token_type=Bearer",
				accessToken.getValue(), idToken.serialize(), state.getValue()));
	}

	@Test
	@WithMockUser
	public void implicitWithIdTokenAndToken_withoutScope_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(implicitWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?response_type=id_token token&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("http://example.com?error_description=*&error=" + error.getCode()));
	}

	@Test
	@WithMockUser
	public void implicitWithIdTokenAndToken_withoutClientId_isError() throws Exception {
		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(implicitWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=id_token token&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest());
	}

	@Test
	@WithMockUser
	public void implicitWithIdTokenAndToken_withoutRedirectUri_isError() throws Exception {
		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(implicitWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=id_token token&client_id=test-client&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest());
	}

	@Test
	@WithMockUser
	public void implicitWithIdTokenAndToken_withoutNonce_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(implicitWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("http://example.com?error_description=*&error=" + error.getCode()));
	}

	@Test
	@WithMockUser
	public void hybridWithIdTokenAndToken_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(hybridWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrlTemplate(
				"http://example.com#access_token={accessToken}&code={code}&id_token={idToken}&token_type=Bearer",
				accessToken.getValue(), authorizationCode.getValue(), idToken.serialize()));
	}

	@Test
	@WithMockUser
	public void hybridWithIdToken_minimumParams_isSuccess() throws Exception {
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(hybridWithIdTokenClient());
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code id_token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlTemplate("http://example.com#code={code}&id_token={idToken}",
						authorizationCode.getValue(), idToken.serialize()));
	}

	@Test
	@WithMockUser
	public void hybridWithToken_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(hybridWithTokenClient());
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlTemplate(
						"http://example.com#access_token={accessToken}&code={code}&token_type=Bearer",
						accessToken.getValue(), authorizationCode.getValue()));
	}

	@Test
	@WithMockUser
	public void hybridWithIdTokenAndToken_withState_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();
		State state = new State();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(hybridWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test&state="
						+ state.getValue()).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrlTemplate(
				"http://example.com#access_token={accessToken}&code={code}&id_token={idToken}&state={state}&token_type=Bearer",
				accessToken.getValue(), authorizationCode.getValue(), idToken.serialize(), state.getValue()));
	}

	@Test
	@WithMockUser
	public void hybridWithIdTokenAndToken_withoutClientId_isError() throws Exception {
		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(hybridWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code id_token token&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest());
	}

	@Test
	@WithMockUser
	public void hybridWithIdTokenAndToken_withoutRedirectUri_isError() throws Exception {
		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(hybridWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code id_token token&client_id=test-client&state=")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest());
	}

	@Test
	@WithMockUser
	public void invalid_withoutResponseType_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("http://example.com?error_description=*&error=" + error.getCode()));
	}

	private static OIDCClientInformation client(ResponseType responseType, Scope scope) {
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.applyDefaults();
		clientMetadata.setRedirectionURI(URI.create("http://example.com"));
		clientMetadata.setScope(scope);
		clientMetadata.setResponseTypes(Collections.singleton(responseType));

		return new OIDCClientInformation(new ClientID("test-client"), new Date(), clientMetadata,
				new Secret("test-secret"));
	}

	private static OIDCClientInformation authCodeClient() {
		return client(new ResponseType(ResponseType.Value.CODE), new Scope(OIDCScopeValue.OPENID));
	}

	private static OIDCClientInformation implicitWithIdTokenAndTokenClient() {
		return client(new ResponseType(OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN),
				new Scope(OIDCScopeValue.OPENID));
	}

	private static OIDCClientInformation implicitWithIdTokenClient() {
		return client(new ResponseType(OIDCResponseTypeValue.ID_TOKEN), new Scope(OIDCScopeValue.OPENID));
	}

	private static OIDCClientInformation hybridWithIdTokenAndTokenClient() {
		return client(
				new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN),
				new Scope(OIDCScopeValue.OPENID));
	}

	private static OIDCClientInformation hybridWithIdTokenClient() {
		return client(new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN),
				new Scope(OIDCScopeValue.OPENID));
	}

	private static OIDCClientInformation hybridWithTokenClient() {
		return client(new ResponseType(ResponseType.Value.CODE, ResponseType.Value.TOKEN),
				new Scope(OIDCScopeValue.OPENID));
	}

}
