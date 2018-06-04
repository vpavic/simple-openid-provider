package io.github.vpavic.oauth2.grant.code;

import java.net.URI;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.token.AccessTokenRequest;
import io.github.vpavic.oauth2.token.AccessTokenService;
import io.github.vpavic.oauth2.token.IdTokenRequest;
import io.github.vpavic.oauth2.token.IdTokenService;
import io.github.vpavic.oauth2.token.RefreshTokenService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

/**
 * Tests for {@link AuthorizationCodeGrantHandler}.
 */
class AuthorizationCodeGrantHandlerTests {

	private ClientRepository clientRepository = mock(ClientRepository.class);

	private AccessTokenService accessTokenService = mock(AccessTokenService.class);

	private RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);

	private IdTokenService idTokenService = mock(IdTokenService.class);

	private AuthorizationCodeService authorizationCodeService = mock(AuthorizationCodeService.class);

	private AuthorizationCodeGrantHandler grantHandler;

	@BeforeEach
	void setUp() {
		reset(this.clientRepository);
		reset(this.accessTokenService);
		reset(this.refreshTokenService);
		reset(this.idTokenService);
		reset(this.authorizationCodeService);
	}

	@Test
	void grant_ValidBasicAuthRequest_ShouldReturnTokens() throws Exception {
		ClientID clientId = new ClientID("test-client");
		URI redirectUri = URI.create("http://example.com/cb");
		AuthorizationCode authorizationCode = new AuthorizationCode();
		AuthorizationCodeContext context = new AuthorizationCodeContext(new Subject("test-user"), clientId, redirectUri,
				new Scope(OIDCScopeValue.OPENID), Instant.now(), new ACR("1"), Collections.singletonList(AMR.PWD),
				new SessionID("test-session"), null, null, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findById(eq(clientId)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.idTokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);
		this.grantHandler = new AuthorizationCodeGrantHandler(this.clientRepository, this.accessTokenService,
				this.refreshTokenService, this.idTokenService, this.authorizationCodeService);

		ClientSecretBasic clientAuth = new ClientSecretBasic(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://example.com/token"), clientAuth,
				new AuthorizationCodeGrant(authorizationCode, redirectUri));
		Tokens tokens = this.grantHandler.grant(tokenRequest);

		assertThat(tokens).isInstanceOf(OIDCTokens.class);
		assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
		assertThat(tokens.getRefreshToken()).isNull();
		assertThat(((OIDCTokens) tokens).getIDTokenString()).isEqualTo(idToken.serialize());
	}

	@Test
	void grant_ValidPostAuthRequest_ShouldReturnTokens() throws Exception {
		ClientID clientId = new ClientID("test-client");
		URI redirectUri = URI.create("http://example.com/cb");
		AuthorizationCode authorizationCode = new AuthorizationCode();
		AuthorizationCodeContext context = new AuthorizationCodeContext(new Subject("test-user"), clientId, redirectUri,
				new Scope(OIDCScopeValue.OPENID), Instant.now(), new ACR("1"), Collections.singletonList(AMR.PWD),
				new SessionID("test-session"), null, null, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findById(eq(clientId)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_POST));
		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.idTokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);
		this.grantHandler = new AuthorizationCodeGrantHandler(this.clientRepository, this.accessTokenService,
				this.refreshTokenService, this.idTokenService, this.authorizationCodeService);

		ClientSecretPost clientAuth = new ClientSecretPost(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://example.com/token"), clientAuth,
				new AuthorizationCodeGrant(authorizationCode, redirectUri));
		Tokens tokens = this.grantHandler.grant(tokenRequest);

		assertThat(tokens).isInstanceOf(OIDCTokens.class);
		assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
		assertThat(tokens.getRefreshToken()).isNull();
		assertThat(((OIDCTokens) tokens).getIDTokenString()).isEqualTo(idToken.serialize());
	}

	@Test
	void grant_MissingContext_ShouldThrowException() {
		this.grantHandler = new AuthorizationCodeGrantHandler(this.clientRepository, this.accessTokenService,
				this.refreshTokenService, this.idTokenService, this.authorizationCodeService);

		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("bad-client"), new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://example.com/token"), clientAuth,
				new AuthorizationCodeGrant(new AuthorizationCode(), URI.create("http://example.com/cb")));

		assertThatThrownBy(() -> this.grantHandler.grant(tokenRequest)).isInstanceOf(GeneralException.class).satisfies(
				e -> assertThat(((GeneralException) e).getErrorObject()).isEqualTo(OAuth2Error.INVALID_GRANT));
	}

	@Test
	void grant_InvalidClientId_ShouldThrowException() throws Exception {
		URI redirectUri = URI.create("http://example.com/cb");
		AuthorizationCode authorizationCode = new AuthorizationCode();
		AuthorizationCodeContext context = new AuthorizationCodeContext(new Subject("test-user"),
				new ClientID("test-client"), redirectUri, new Scope(OIDCScopeValue.OPENID), Instant.now(), new ACR("1"),
				Collections.singletonList(AMR.PWD), new SessionID("test-session"), null, null, null);

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		this.grantHandler = new AuthorizationCodeGrantHandler(this.clientRepository, this.accessTokenService,
				this.refreshTokenService, this.idTokenService, this.authorizationCodeService);

		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("bad-client"), new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://example.com/token"), clientAuth,
				new AuthorizationCodeGrant(authorizationCode, redirectUri));

		assertThatThrownBy(() -> this.grantHandler.grant(tokenRequest)).isInstanceOf(GeneralException.class).satisfies(
				e -> assertThat(((GeneralException) e).getErrorObject()).isEqualTo(OAuth2Error.INVALID_GRANT));
	}

	@Test
	void grant_InvalidRedirectUri_ShouldThrowException() throws Exception {
		ClientID clientId = new ClientID("test-client");
		AuthorizationCode authorizationCode = new AuthorizationCode();
		AuthorizationCodeContext context = new AuthorizationCodeContext(new Subject("test-user"), clientId,
				URI.create("http://example.com/cb"), new Scope(OIDCScopeValue.OPENID), Instant.now(), new ACR("1"),
				Collections.singletonList(AMR.PWD), new SessionID("test-session"), null, null, null);

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		this.grantHandler = new AuthorizationCodeGrantHandler(this.clientRepository, this.accessTokenService,
				this.refreshTokenService, this.idTokenService, this.authorizationCodeService);

		ClientSecretBasic clientAuth = new ClientSecretBasic(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://example.com/token"), clientAuth,
				new AuthorizationCodeGrant(authorizationCode, URI.create("http://example.com/cb2")));

		assertThatThrownBy(() -> this.grantHandler.grant(tokenRequest)).isInstanceOf(GeneralException.class).satisfies(
				e -> assertThat(((GeneralException) e).getErrorObject()).isEqualTo(OAuth2Error.INVALID_GRANT));
	}

	@Test
	void grant_ValidPlainPkceRequest_ShouldReturnTokens() throws Exception {
		ClientID clientId = new ClientID("test-client");
		URI redirectUri = URI.create("http://example.com/cb");
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.PLAIN;
		CodeVerifier codeVerifier = new CodeVerifier();
		AuthorizationCode authorizationCode = new AuthorizationCode();
		AuthorizationCodeContext context = new AuthorizationCodeContext(new Subject("test-user"), clientId, redirectUri,
				new Scope(OIDCScopeValue.OPENID), Instant.now(), new ACR("1"), Collections.singletonList(AMR.PWD),
				new SessionID("test-session"), CodeChallenge.compute(codeChallengeMethod, codeVerifier),
				codeChallengeMethod, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findById(any(ClientID.class))).willReturn(client(ClientAuthenticationMethod.NONE));
		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.idTokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);
		this.grantHandler = new AuthorizationCodeGrantHandler(this.clientRepository, this.accessTokenService,
				this.refreshTokenService, this.idTokenService, this.authorizationCodeService);

		TokenRequest tokenRequest = new TokenRequest(URI.create("http://example.com/token"), clientId,
				new AuthorizationCodeGrant(authorizationCode, redirectUri, codeVerifier));
		Tokens tokens = this.grantHandler.grant(tokenRequest);

		assertThat(tokens).isInstanceOf(OIDCTokens.class);
		assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
		assertThat(tokens.getRefreshToken()).isNull();
		assertThat(((OIDCTokens) tokens).getIDTokenString()).isEqualTo(idToken.serialize());
	}

	@Test
	void grant_ValidS256PkceS256Request_ShouldReturnTokens() throws Exception {
		ClientID clientId = new ClientID("test-client");
		URI redirectUri = URI.create("http://example.com/cb");
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
		CodeVerifier codeVerifier = new CodeVerifier();
		AuthorizationCode authorizationCode = new AuthorizationCode();
		AuthorizationCodeContext context = new AuthorizationCodeContext(new Subject("test-user"), clientId, redirectUri,
				new Scope(OIDCScopeValue.OPENID), Instant.now(), new ACR("1"), Collections.singletonList(AMR.PWD),
				new SessionID("test-session"), CodeChallenge.compute(codeChallengeMethod, codeVerifier),
				codeChallengeMethod, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findById(any(ClientID.class))).willReturn(client(ClientAuthenticationMethod.NONE));
		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.accessTokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.idTokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);
		this.grantHandler = new AuthorizationCodeGrantHandler(this.clientRepository, this.accessTokenService,
				this.refreshTokenService, this.idTokenService, this.authorizationCodeService);

		TokenRequest tokenRequest = new TokenRequest(URI.create("http://example.com/token"), clientId,
				new AuthorizationCodeGrant(authorizationCode, URI.create("http://example.com/cb"), codeVerifier));
		Tokens tokens = this.grantHandler.grant(tokenRequest);

		assertThat(tokens).isInstanceOf(OIDCTokens.class);
		assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
		assertThat(tokens.getRefreshToken()).isNull();
		assertThat(((OIDCTokens) tokens).getIDTokenString()).isEqualTo(idToken.serialize());
	}

	// TODO add more tests

	private static OIDCClientInformation client(ClientAuthenticationMethod clientAuthenticationMethod) {
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.applyDefaults();
		clientMetadata.setRedirectionURI(URI.create("http://example.com/cb"));
		clientMetadata.setScope(new Scope(OIDCScopeValue.OPENID));
		clientMetadata.setResponseTypes(Collections.singleton(new ResponseType(ResponseType.Value.CODE)));
		clientMetadata.setTokenEndpointAuthMethod(clientAuthenticationMethod);

		return new OIDCClientInformation(new ClientID("test-client"), new Date(), clientMetadata,
				ClientAuthenticationMethod.NONE.equals(clientAuthenticationMethod) ? null : new Secret("test-secret"));
	}

}
