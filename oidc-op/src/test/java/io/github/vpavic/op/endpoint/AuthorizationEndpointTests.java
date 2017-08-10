package io.github.vpavic.op.endpoint;

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
import com.nimbusds.openid.connect.sdk.Nonce;
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
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.AuthenticatedPrincipal;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
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
				.andExpect(redirectedUrl("http://example.com?code={code}&session_state={sessionState}",
						authorizationCode.getValue(), this.session.getId()));
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
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}&state={state}&session_state={sessionState}",
						authorizationCode.getValue(), state.getValue(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void authCode_withoutScope_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void authCode_withoutScopeWithInvalidRedirectUri_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://invalid.example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void authCode_withInvalidScope_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=test&response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void authCode_withoutClientId_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void authCode_withoutRedirectUri_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code&client_id=test-client").session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void authCode_withInvalidRedirectUri_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://invalid.example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void implicitWithIdTokenAndToken_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(implicitWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AuthenticatedPrincipal.class), any(ClientID.class),
				any(Scope.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(AuthenticatedPrincipal.class), any(ClientID.class), any(Scope.class),
				any(Nonce.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&id_token={idToken}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), idToken.serialize(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void implicitWithIdToken_minimumParams_isSuccess() throws Exception {
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(implicitWithIdTokenClient());
		given(this.tokenService.createIdToken(any(AuthenticatedPrincipal.class), any(ClientID.class), any(Scope.class),
				any(Nonce.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=id_token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com#id_token={idToken}&session_state={sessionState}",
						idToken.serialize(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void implicitWithIdTokenAndToken_withState_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		State state = new State();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(implicitWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AuthenticatedPrincipal.class), any(ClientID.class),
				any(Scope.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(AuthenticatedPrincipal.class), any(ClientID.class), any(Scope.class),
				any(Nonce.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test&state="
						+ state.getValue()).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&id_token={idToken}&state={state}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), idToken.serialize(), state.getValue(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void implicitWithIdTokenAndToken_withoutScope_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(implicitWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void implicitWithIdTokenAndToken_withoutClientId_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(implicitWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=id_token token&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void implicitWithIdTokenAndToken_withoutRedirectUri_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(implicitWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=id_token token&client_id=test-client&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
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
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void hybridWithIdTokenAndToken_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(hybridWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AuthenticatedPrincipal.class), any(ClientID.class),
				any(Scope.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(AuthenticatedPrincipal.class), any(ClientID.class), any(Scope.class),
				any(Nonce.class))).willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&code={code}&id_token={idToken}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), authorizationCode.getValue(), idToken.serialize(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void hybridWithIdToken_minimumParams_isSuccess() throws Exception {
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(hybridWithIdTokenClient());
		given(this.tokenService.createIdToken(any(AuthenticatedPrincipal.class), any(ClientID.class), any(Scope.class),
				any(Nonce.class))).willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code id_token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(
				redirectedUrl("http://example.com#code={code}&id_token={idToken}&session_state={sessionState}",
						authorizationCode.getValue(), idToken.serialize(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void hybridWithToken_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(hybridWithTokenClient());
		given(this.tokenService.createAccessToken(any(AuthenticatedPrincipal.class), any(ClientID.class),
				any(Scope.class))).willReturn(accessToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&code={code}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), authorizationCode.getValue(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void hybridWithIdTokenAndToken_withState_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();
		State state = new State();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(hybridWithIdTokenAndTokenClient());
		given(this.tokenService.createAccessToken(any(AuthenticatedPrincipal.class), any(ClientID.class),
				any(Scope.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(AuthenticatedPrincipal.class), any(ClientID.class), any(Scope.class),
				any(Nonce.class))).willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test&state="
						+ state.getValue()).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&code={code}&id_token={idToken}&state={state}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), authorizationCode.getValue(), idToken.serialize(), state.getValue(),
				this.session.getId()));
	}

	@Test
	@WithMockUser
	public void hybridWithIdTokenAndToken_withoutClientId_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(hybridWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code id_token token&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void hybridWithIdTokenAndToken_withoutRedirectUri_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(hybridWithIdTokenAndTokenClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&response_type=code id_token token&client_id=test-client&state=")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
	}

	@Test
	@WithMockUser
	public void invalid_withoutResponseType_isError() throws Exception {
		ErrorObject error = OAuth2Error.INVALID_REQUEST;

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(authCodeClient());

		MockHttpServletRequestBuilder request = get(
				"/oauth2/authorize?scope=openid&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isBadRequest())
				.andExpect(content().string(containsString(error.getCode())));
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
