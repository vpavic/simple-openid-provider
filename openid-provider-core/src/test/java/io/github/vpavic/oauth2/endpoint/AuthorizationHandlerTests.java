package io.github.vpavic.oauth2.endpoint;

import java.net.URI;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeContext;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeService;
import io.github.vpavic.oauth2.scope.ScopeResolver;
import io.github.vpavic.oauth2.token.AccessTokenRequest;
import io.github.vpavic.oauth2.token.AccessTokenService;
import io.github.vpavic.oauth2.token.IdTokenRequest;
import io.github.vpavic.oauth2.token.IdTokenService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.AdditionalAnswers.returnsSecondArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

/**
 * Tests for {@link AuthorizationHandlerTests}.
 */
class AuthorizationHandlerTests {

	private ClientRepository clientRepository = mock(ClientRepository.class);

	private AuthorizationCodeService authorizationCodeService = mock(AuthorizationCodeService.class);

	private AccessTokenService accessTokenService = mock(AccessTokenService.class);

	private IdTokenService idTokenService = mock(IdTokenService.class);

	private ScopeResolver scopeResolver = mock(ScopeResolver.class);

	private AuthorizationHandler authorizationHandler;

	@BeforeEach
	void setUp() {
		reset(this.clientRepository);
		reset(this.authorizationCodeService);
		reset(this.idTokenService);
		reset(this.scopeResolver);
	}

	@Test
	void authCode_minimumParams_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);
		given(this.scopeResolver.resolve(eq(subject), eq(Scope.parse("openid")), any(OIDCClientMetadata.class)))
				.will(returnsSecondArg());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com", subject,
				Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationSuccessResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAuthorizationCode())
				.isEqualTo(authorizationCode);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAccessToken()).isNull();
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getIDToken()).isNull();
	}

	@Test
	void authCode_withState_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();
		Subject subject = new Subject("user");
		State state = new State();

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);
		given(this.scopeResolver.resolve(eq(subject), eq(Scope.parse("openid")), any(OIDCClientMetadata.class)))
				.will(returnsSecondArg());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com&state="
						+ state.getValue(),
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationSuccessResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isEqualTo(state);
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAuthorizationCode())
				.isEqualTo(authorizationCode);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAccessToken()).isNull();
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getIDToken()).isNull();
	}

	@Test
	void authCode_withPromptLogin_isRequireLogin() {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);

		assertThatThrownBy(() -> this.authorizationHandler.authorize(
				"scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com&prompt=login",
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test")))
						.isInstanceOf(LoginRequiredException.class);
	}

	@Test
	void authCode_withPromptNoneAndAuthentication_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);
		given(this.scopeResolver.resolve(eq(subject), eq(Scope.parse("openid")), any(OIDCClientMetadata.class)))
				.will(returnsSecondArg());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com&prompt=none",
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationSuccessResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAuthorizationCode())
				.isEqualTo(authorizationCode);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAccessToken()).isNull();
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getIDToken()).isNull();
	}

	@Test
	void authCode_withPromptNoneAndNoAuthentication_isError() throws Exception {
		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com&prompt=none",
				null, null, null, null, null);

		assertThat(authorizationResponse).isInstanceOf(AuthenticationErrorResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
		assertThat(((AuthenticationErrorResponse) authorizationResponse).getErrorObject())
				.isEqualTo(OIDCError.LOGIN_REQUIRED);
	}

	@Test
	void authCode_withValidMaxAge_isSuccess() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);
		given(this.scopeResolver.resolve(eq(subject), eq(Scope.parse("openid")), any(OIDCClientMetadata.class)))
				.will(returnsSecondArg());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com&max_age=60",
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationSuccessResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAuthorizationCode())
				.isEqualTo(authorizationCode);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAccessToken()).isNull();
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getIDToken()).isNull();
	}

	@Test
	void authCode_withExpiredMaxAge_isRequireLogin() {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);

		assertThatThrownBy(() -> this.authorizationHandler.authorize(
				"scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com&max_age=1",
				subject, Instant.now().minusSeconds(2), new ACR("1"), Collections.emptyList(), new SessionID("test")))
						.isInstanceOf(LoginRequiredException.class);
	}

	@Test
	void authCode_withoutScope_isError() throws Exception {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"response_type=code&client_id=test-client&redirect_uri=http://example.com", subject, Instant.now(),
				new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationErrorResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
		assertThat(((AuthenticationErrorResponse) authorizationResponse).getErrorObject())
				.isEqualTo(OAuth2Error.INVALID_REQUEST);
	}

	@Test
	void authCode_withoutScopeWithInvalidRedirectUri_isError() {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);

		assertThatThrownBy(() -> this.authorizationHandler.authorize(
				"response_type=code&client_id=test-client&redirect_uri=http://invalid.example.com", subject,
				Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test")))
						.isInstanceOf(NonRedirectingException.class);
	}

	@Test
	void authCode_withInvalidScope_isError() throws Exception {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=test&response_type=code&client_id=test-client&redirect_uri=http://example.com", subject,
				Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationErrorResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
		assertThat(((AuthenticationErrorResponse) authorizationResponse).getErrorObject())
				.isEqualTo(OAuth2Error.INVALID_REQUEST);
	}

	@Test
	void authCode_withoutClientId_isError() {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);

		assertThatThrownBy(() -> this.authorizationHandler.authorize(
				"scope=openid&response_type=code&redirect_uri=http://example.com", subject, Instant.now(), new ACR("1"),
				Collections.emptyList(), new SessionID("test"))).isInstanceOf(NonRedirectingException.class);
	}

	@Test
	void authCode_withoutRedirectUri_isError() {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);

		assertThatThrownBy(
				() -> this.authorizationHandler.authorize("scope=openid&response_type=code&client_id=test-client",
						subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test")))
								.isInstanceOf(NonRedirectingException.class);
	}

	@Test
	void authCode_withInvalidRedirectUri_isError() {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);

		assertThatThrownBy(() -> this.authorizationHandler.authorize(
				"scope=openid&response_type=code&client_id=test-client&redirect_uri=http://invalid.example.com",
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test")))
						.isInstanceOf(NonRedirectingException.class);
	}

	@Test
	void implicitWithIdTokenAndToken_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client"))))
				.willReturn(implicitWithIdTokenAndTokenClient());
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.idTokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);
		given(this.scopeResolver.resolve(eq(subject), eq(Scope.parse("openid")), any(OIDCClientMetadata.class)))
				.will(returnsSecondArg());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test",
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationSuccessResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAuthorizationCode()).isNull();
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAccessToken()).isEqualTo(accessToken);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getIDToken()).isEqualTo(idToken);
	}

	@Test
	void implicitWithIdToken_minimumParams_isSuccess() throws Exception {
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(implicitWithIdTokenClient());
		given(this.idTokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);
		given(this.scopeResolver.resolve(eq(subject), eq(Scope.parse("openid")), any(OIDCClientMetadata.class)))
				.will(returnsSecondArg());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&response_type=id_token&client_id=test-client&redirect_uri=http://example.com&nonce=test",
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationSuccessResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAuthorizationCode()).isNull();
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAccessToken()).isNull();
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getIDToken()).isEqualTo(idToken);
	}

	@Test
	void implicitWithIdTokenAndToken_withState_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		Subject subject = new Subject("user");
		State state = new State();

		given(this.clientRepository.findById(eq(new ClientID("test-client"))))
				.willReturn(implicitWithIdTokenAndTokenClient());
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.idTokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);
		given(this.scopeResolver.resolve(eq(subject), eq(Scope.parse("openid")), any(OIDCClientMetadata.class)))
				.will(returnsSecondArg());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test&state="
						+ state.getValue(),
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationSuccessResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isEqualTo(state);
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAuthorizationCode()).isNull();
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAccessToken()).isEqualTo(accessToken);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getIDToken()).isEqualTo(idToken);
	}

	@Test
	void implicitWithIdTokenAndToken_withoutScope_isError() throws Exception {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client"))))
				.willReturn(implicitWithIdTokenAndTokenClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test",
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationErrorResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(((AuthenticationErrorResponse) authorizationResponse).getErrorObject())
				.isEqualTo(OAuth2Error.INVALID_REQUEST);
	}

	@Test
	void implicitWithIdTokenAndToken_withoutClientId_isError() {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client"))))
				.willReturn(implicitWithIdTokenAndTokenClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);

		assertThatThrownBy(() -> this.authorizationHandler.authorize(
				"scope=openid&response_type=id_token token&redirect_uri=http://example.com&nonce=test", subject,
				Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test")))
						.isInstanceOf(NonRedirectingException.class);
	}

	@Test
	void implicitWithIdTokenAndToken_withoutRedirectUri_isError() {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client"))))
				.willReturn(implicitWithIdTokenAndTokenClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);

		assertThatThrownBy(() -> this.authorizationHandler.authorize(
				"scope=openid&response_type=id_token token&client_id=test-client&nonce=test", subject, Instant.now(),
				new ACR("1"), Collections.emptyList(), new SessionID("test")))
						.isInstanceOf(NonRedirectingException.class);
	}

	@Test
	void implicitWithIdTokenAndToken_withoutNonce_isError() throws Exception {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client"))))
				.willReturn(implicitWithIdTokenAndTokenClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com",
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationErrorResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(((AuthenticationErrorResponse) authorizationResponse).getErrorObject())
				.isEqualTo(OAuth2Error.INVALID_REQUEST);
	}

	@Test
	void hybridWithIdTokenAndToken_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client"))))
				.willReturn(hybridWithIdTokenAndTokenClient());
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.idTokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);
		given(this.scopeResolver.resolve(eq(subject), eq(Scope.parse("openid")), any(OIDCClientMetadata.class)))
				.will(returnsSecondArg());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&response_type=code id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test",
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationSuccessResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAuthorizationCode())
				.isEqualTo(authorizationCode);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAccessToken()).isEqualTo(accessToken);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getIDToken()).isEqualTo(idToken);
	}

	@Test
	void hybridWithIdToken_minimumParams_isSuccess() throws Exception {
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(hybridWithIdTokenClient());
		given(this.idTokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);
		given(this.scopeResolver.resolve(eq(subject), eq(Scope.parse("openid")), any(OIDCClientMetadata.class)))
				.will(returnsSecondArg());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&response_type=code id_token&client_id=test-client&redirect_uri=http://example.com&nonce=test",
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationSuccessResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAuthorizationCode())
				.isEqualTo(authorizationCode);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAccessToken()).isNull();
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getIDToken()).isEqualTo(idToken);
	}

	@Test
	void hybridWithToken_minimumParams_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		AuthorizationCode authorizationCode = new AuthorizationCode();
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(hybridWithTokenClient());
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);
		given(this.scopeResolver.resolve(eq(subject), eq(Scope.parse("openid")), any(OIDCClientMetadata.class)))
				.will(returnsSecondArg());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&response_type=code token&client_id=test-client&redirect_uri=http://example.com&nonce=test",
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationSuccessResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAuthorizationCode())
				.isEqualTo(authorizationCode);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAccessToken()).isEqualTo(accessToken);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getIDToken()).isNull();
	}

	@Test
	void hybridWithIdTokenAndToken_withState_isSuccess() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();
		Subject subject = new Subject("user");
		State state = new State();

		given(this.clientRepository.findById(eq(new ClientID("test-client"))))
				.willReturn(hybridWithIdTokenAndTokenClient());
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.idTokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);
		given(this.scopeResolver.resolve(eq(subject), eq(Scope.parse("openid")), any(OIDCClientMetadata.class)))
				.will(returnsSecondArg());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&response_type=code id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test&state="
						+ state.getValue(),
				subject, Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationSuccessResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isEqualTo(state);
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAuthorizationCode())
				.isEqualTo(authorizationCode);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getAccessToken()).isEqualTo(accessToken);
		assertThat(((AuthenticationSuccessResponse) authorizationResponse).getIDToken()).isEqualTo(idToken);
	}

	@Test
	void hybridWithIdTokenAndToken_withoutClientId_isError() {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client"))))
				.willReturn(hybridWithIdTokenAndTokenClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);

		assertThatThrownBy(() -> this.authorizationHandler.authorize(
				"scope=openid&response_type=code id_token token&redirect_uri=http://example.com&nonce=test", subject,
				Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test")))
						.isInstanceOf(NonRedirectingException.class);
	}

	@Test
	void hybridWithIdTokenAndToken_withoutRedirectUri_isError() {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client"))))
				.willReturn(hybridWithIdTokenAndTokenClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);

		assertThatThrownBy(() -> this.authorizationHandler.authorize(
				"scope=openid&response_type=code id_token token&client_id=test-client&nonce=test", subject,
				Instant.now(), new ACR("1"), Collections.emptyList(), new SessionID("test")))
						.isInstanceOf(NonRedirectingException.class);
	}

	@Test
	void invalid_withoutResponseType_isError() throws Exception {
		Subject subject = new Subject("user");

		given(this.clientRepository.findById(eq(new ClientID("test-client")))).willReturn(authCodeClient());

		this.authorizationHandler = new AuthorizationHandler(this.clientRepository, this.authorizationCodeService,
				this.accessTokenService, this.idTokenService, this.scopeResolver);
		AuthorizationResponse authorizationResponse = this.authorizationHandler.authorize(
				"scope=openid&client_id=test-client&redirect_uri=http://example.com", subject, Instant.now(),
				new ACR("1"), Collections.emptyList(), new SessionID("test"));

		assertThat(authorizationResponse).isInstanceOf(AuthenticationErrorResponse.class);
		assertThat(authorizationResponse.getRedirectionURI()).isEqualTo(URI.create("http://example.com"));
		assertThat(authorizationResponse.getState()).isNull();
		assertThat(authorizationResponse.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
		assertThat(((AuthenticationErrorResponse) authorizationResponse).getErrorObject())
				.isEqualTo(OAuth2Error.INVALID_REQUEST);
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
