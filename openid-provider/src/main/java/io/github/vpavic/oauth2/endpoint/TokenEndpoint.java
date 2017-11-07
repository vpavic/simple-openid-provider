package io.github.vpavic.oauth2.endpoint;

import java.time.Instant;
import java.util.Objects;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import io.github.vpavic.oauth2.authentication.ClientRequestValidator;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.code.AuthorizationCodeContext;
import io.github.vpavic.oauth2.code.AuthorizationCodeService;
import io.github.vpavic.oauth2.token.AccessTokenRequest;
import io.github.vpavic.oauth2.token.IdTokenRequest;
import io.github.vpavic.oauth2.token.RefreshTokenContext;
import io.github.vpavic.oauth2.token.RefreshTokenRequest;
import io.github.vpavic.oauth2.token.RefreshTokenStore;
import io.github.vpavic.oauth2.token.TokenService;

/**
 * OAuth 2.0 and OpenID Connect 1.0 compatible Token Endpoint implementation.
 *
 * @author Vedran Pavic
 * @see <a href="https://tools.ietf.org/html/rfc6749">RFC 6749: The OAuth 2.0 Authorization Framework</a>
 * @see <a href="https://tools.ietf.org/html/rfc7636">RFC 7636: Proof Key for Code Exchange by OAuth Public Clients</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
@RequestMapping(path = TokenEndpoint.PATH_MAPPING)
public class TokenEndpoint {

	public static final String PATH_MAPPING = "/oauth2/token";

	private final ClientRepository clientRepository;

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	private final AuthenticationManager authenticationManager;

	private final RefreshTokenStore refreshTokenStore;

	private final ClientRequestValidator clientRequestValidator;

	private boolean updateRefreshToken;

	public TokenEndpoint(Issuer issuer, ClientRepository clientRepository,
			AuthorizationCodeService authorizationCodeService, TokenService tokenService,
			AuthenticationManager authenticationManager, RefreshTokenStore refreshTokenStore) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(authorizationCodeService, "authorizationCodeService must not be null");
		Objects.requireNonNull(tokenService, "tokenService must not be null");
		Objects.requireNonNull(authenticationManager, "authenticationManager must not be null");
		Objects.requireNonNull(refreshTokenStore, "refreshTokenStore must not be null");

		this.clientRepository = clientRepository;
		this.authorizationCodeService = authorizationCodeService;
		this.tokenService = tokenService;
		this.authenticationManager = authenticationManager;
		this.refreshTokenStore = refreshTokenStore;
		this.clientRequestValidator = new ClientRequestValidator(issuer, clientRepository);
	}

	public void setUpdateRefreshToken(boolean updateRefreshToken) {
		this.updateRefreshToken = updateRefreshToken;
	}

	@PostMapping(produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<String> handleTokenRequest(HTTPRequest httpRequest) throws Exception {
		TokenRequest tokenRequest = TokenRequest.parse(httpRequest);
		this.clientRequestValidator.validateRequest(tokenRequest);
		AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();
		ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();
		Scope scope = tokenRequest.getScope();
		AccessTokenResponse tokenResponse;

		if (authorizationGrant instanceof AuthorizationCodeGrant) {
			tokenResponse = handleAuthorizationCodeGrantType((AuthorizationCodeGrant) authorizationGrant);
		}
		else if (authorizationGrant instanceof ResourceOwnerPasswordCredentialsGrant) {
			tokenResponse = handleResourceOwnerPasswordCredentialsGrantType(
					(ResourceOwnerPasswordCredentialsGrant) authorizationGrant, clientAuthentication, scope);
		}
		else if (authorizationGrant instanceof ClientCredentialsGrant) {
			tokenResponse = handleClientCredentialsGrantType(clientAuthentication, scope);
		}
		else if (authorizationGrant instanceof RefreshTokenGrant) {
			tokenResponse = handleRefreshTokenGrantType((RefreshTokenGrant) authorizationGrant);
		}
		else {
			throw new GeneralException(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		}

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(tokenResponse.toJSONObject().toJSONString());
		// @formatter:on
	}

	private AccessTokenResponse handleAuthorizationCodeGrantType(AuthorizationCodeGrant authorizationCodeGrant)
			throws GeneralException {
		AuthorizationCodeContext context = this.authorizationCodeService
				.consume(authorizationCodeGrant.getAuthorizationCode());

		if (context == null) {
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}

		CodeChallenge codeChallenge = context.getCodeChallenge();

		if (codeChallenge != null) {
			CodeChallengeMethod codeChallengeMethod = context.getCodeChallengeMethod();

			if (codeChallengeMethod == null) {
				codeChallengeMethod = CodeChallengeMethod.PLAIN;
			}

			CodeVerifier codeVerifier = authorizationCodeGrant.getCodeVerifier();

			if (codeVerifier == null
					|| !codeChallenge.equals(CodeChallenge.compute(codeChallengeMethod, codeVerifier))) {
				throw new GeneralException(OAuth2Error.INVALID_REQUEST);
			}
		}

		Subject subject = context.getSubject();
		ClientID clientId = context.getClientId();
		Scope scope = context.getScope();
		Instant authenticationTime = context.getAuthenticationTime();
		ACR acr = context.getAcr();
		AMR amr = context.getAmr();
		SessionID sessionId = context.getSessionId();
		Nonce nonce = context.getNonce();

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, scope);
		AccessToken accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		RefreshToken refreshToken = null;

		if (client.getOIDCMetadata().getGrantTypes().contains(GrantType.REFRESH_TOKEN)
				|| scope.contains(OIDCScopeValue.OFFLINE_ACCESS)) {
			RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(subject, clientId, scope);
			refreshToken = this.tokenService.createRefreshToken(refreshTokenRequest);
		}

		IdTokenRequest idTokenRequest = new IdTokenRequest(subject, client, scope, authenticationTime, acr, amr,
				sessionId, nonce, accessToken, null);
		JWT idToken = this.tokenService.createIdToken(idTokenRequest);
		OIDCTokens tokens = new OIDCTokens(idToken.serialize(), accessToken, refreshToken);

		return new OIDCTokenResponse(tokens);
	}

	private AccessTokenResponse handleResourceOwnerPasswordCredentialsGrantType(
			ResourceOwnerPasswordCredentialsGrant passwordCredentialsGrant, ClientAuthentication clientAuthentication,
			Scope scope) throws GeneralException {
		String username = passwordCredentialsGrant.getUsername();
		Secret password = passwordCredentialsGrant.getPassword();

		Authentication authentication;

		try {
			authentication = this.authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(username, password.getValue()));
		}
		catch (AuthenticationException e) {
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}

		Subject subject = new Subject(authentication.getName());
		ClientID clientId = clientAuthentication.getClientID();

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, scope);
		AccessToken accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		RefreshToken refreshToken = null;

		if (client.getOIDCMetadata().getGrantTypes().contains(GrantType.REFRESH_TOKEN)) {
			RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(subject, clientId, scope);
			refreshToken = this.tokenService.createRefreshToken(refreshTokenRequest);
		}

		Tokens tokens = new Tokens(accessToken, refreshToken);

		return new AccessTokenResponse(tokens);
	}

	private AccessTokenResponse handleClientCredentialsGrantType(ClientAuthentication clientAuthentication,
			Scope scope) {
		ClientID clientId = clientAuthentication.getClientID();
		Subject subject = new Subject(clientId.getValue());

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, scope);
		AccessToken accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		Tokens tokens = new Tokens(accessToken, null);

		return new AccessTokenResponse(tokens);
	}

	private AccessTokenResponse handleRefreshTokenGrantType(RefreshTokenGrant refreshTokenGrant)
			throws GeneralException {
		RefreshToken refreshToken = refreshTokenGrant.getRefreshToken();

		RefreshTokenContext context = this.refreshTokenStore.load(refreshToken);
		Subject subject = context.getSubject();
		ClientID clientId = context.getClientId();
		Scope scope = context.getScope();

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(subject, client, scope);
		AccessToken accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		RefreshToken updatedRefreshToken = null;

		if (this.updateRefreshToken) {
			this.refreshTokenStore.revoke(refreshToken);
			RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(subject, clientId, scope);
			updatedRefreshToken = this.tokenService.createRefreshToken(refreshTokenRequest);
		}

		Tokens tokens = new Tokens(accessToken, updatedRefreshToken);

		return new AccessTokenResponse(tokens);
	}

	@ExceptionHandler(GeneralException.class)
	public ResponseEntity<String> handleParseException(GeneralException e) {
		ErrorObject error = e.getErrorObject();

		if (error == null) {
			error = OAuth2Error.INVALID_REQUEST.setDescription(e.getMessage());
		}

		TokenErrorResponse tokenResponse = new TokenErrorResponse(error);

		// @formatter:off
		return ResponseEntity.status(error.getHTTPStatusCode())
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(tokenResponse.toJSONObject().toJSONString());
		// @formatter:on
	}

}