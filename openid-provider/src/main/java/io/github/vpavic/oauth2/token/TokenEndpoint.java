package io.github.vpavic.oauth2.token;

import java.time.Instant;
import java.util.Objects;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
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
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.ServletWebRequest;

import io.github.vpavic.oauth2.OpenIdProviderProperties;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.client.ClientRequestValidator;

/**
 * OAuth 2.0 and OpenID Connect 1.0 compatible Token Endpoint implementation.
 *
 * @author Vedran Pavic
 * @see <a href="https://tools.ietf.org/html/rfc6749">RFC 6749: The OAuth 2.0 Authorization Framework</a>
 * @see <a href="https://tools.ietf.org/html/rfc7636">RFC 7636: Proof Key for Code Exchange by OAuth Public Clients</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
@Controller
@RequestMapping(path = TokenEndpoint.PATH_MAPPING)
public class TokenEndpoint {

	public static final String PATH_MAPPING = "/oauth2/token";

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	private final AuthenticationManager authenticationManager;

	private final RefreshTokenStore refreshTokenStore;

	private final AccessTokenClaimsMapper accessTokenClaimsMapper;

	private final IdTokenClaimsMapper idTokenClaimsMapper;

	private final ClientRequestValidator clientRequestValidator;

	public TokenEndpoint(OpenIdProviderProperties properties, ClientRepository clientRepository,
			AuthorizationCodeService authorizationCodeService, TokenService tokenService,
			AuthenticationManager authenticationManager, RefreshTokenStore refreshTokenStore,
			AccessTokenClaimsMapper accessTokenClaimsMapper, IdTokenClaimsMapper idTokenClaimsMapper) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(authorizationCodeService, "authorizationCodeService must not be null");
		Objects.requireNonNull(tokenService, "tokenService must not be null");
		Objects.requireNonNull(authenticationManager, "authenticationManager must not be null");
		Objects.requireNonNull(refreshTokenStore, "refreshTokenStore must not be null");
		Objects.requireNonNull(accessTokenClaimsMapper, "claimsMapper must not be null");
		Objects.requireNonNull(idTokenClaimsMapper, "idTokenClaimsMapper must not be null");

		this.properties = properties;
		this.clientRepository = clientRepository;
		this.authorizationCodeService = authorizationCodeService;
		this.tokenService = tokenService;
		this.authenticationManager = authenticationManager;
		this.refreshTokenStore = refreshTokenStore;
		this.accessTokenClaimsMapper = accessTokenClaimsMapper;
		this.idTokenClaimsMapper = idTokenClaimsMapper;
		this.clientRequestValidator = new ClientRequestValidator(properties, clientRepository);
	}

	@PostMapping(produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<String> handleTokenRequest(ServletWebRequest request) throws Exception {
		TokenRequest tokenRequest = resolveTokenRequest(request);

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

	private TokenRequest resolveTokenRequest(ServletWebRequest request) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request.getRequest());
		TokenRequest tokenRequest = TokenRequest.parse(httpRequest);
		this.clientRequestValidator.validateRequest(tokenRequest);

		return tokenRequest;
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

		String principal = context.getPrincipal();
		ClientID clientId = context.getClientId();
		Scope scope = context.getScope();
		Instant authenticationTime = context.getAuthenticationTime();
		ACR acr = context.getAcr();
		AMR amr = context.getAmr();
		String sessionId = context.getSessionId();
		Nonce nonce = context.getNonce();

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(principal, client, scope,
				this.accessTokenClaimsMapper);
		AccessToken accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		RefreshToken refreshToken = null;

		if (scope.contains(OIDCScopeValue.OFFLINE_ACCESS)) {
			RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(principal, clientId, scope);
			refreshToken = this.tokenService.createRefreshToken(refreshTokenRequest);
		}

		IdTokenRequest idTokenRequest = new IdTokenRequest(principal, client, scope, authenticationTime, acr, amr,
				this.idTokenClaimsMapper, sessionId, nonce, accessToken, null, null);
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

		String principal = authentication.getName();
		ClientID clientId = clientAuthentication.getClientID();

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(principal, client, scope,
				this.accessTokenClaimsMapper);
		AccessToken accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		RefreshToken refreshToken = null;

		if (scope.contains(OIDCScopeValue.OFFLINE_ACCESS)) {
			RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(principal, clientId, scope);
			refreshToken = this.tokenService.createRefreshToken(refreshTokenRequest);
		}

		Tokens tokens = new Tokens(accessToken, refreshToken);

		return new AccessTokenResponse(tokens);
	}

	private AccessTokenResponse handleClientCredentialsGrantType(ClientAuthentication clientAuthentication,
			Scope scope) {
		ClientID clientId = clientAuthentication.getClientID();
		String principal = clientId.getValue();

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(principal, client, scope,
				this.accessTokenClaimsMapper);
		AccessToken accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		Tokens tokens = new Tokens(accessToken, null);

		return new AccessTokenResponse(tokens);
	}

	private AccessTokenResponse handleRefreshTokenGrantType(RefreshTokenGrant refreshTokenGrant)
			throws GeneralException {
		RefreshToken refreshToken = refreshTokenGrant.getRefreshToken();

		RefreshTokenContext context = this.refreshTokenStore.load(refreshToken);
		String principal = context.getPrincipal();
		ClientID clientId = context.getClientId();
		Scope scope = context.getScope();

		OIDCClientInformation client = this.clientRepository.findById(clientId);
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest(principal, client, scope,
				this.accessTokenClaimsMapper);
		AccessToken accessToken = this.tokenService.createAccessToken(accessTokenRequest);
		RefreshToken updatedRefreshToken = null;

		if (this.properties.getRefreshToken().isUpdate() && scope.contains(OIDCScopeValue.OFFLINE_ACCESS)) {
			RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(principal, clientId, scope);
			updatedRefreshToken = this.tokenService.createRefreshToken(refreshTokenRequest);
			this.refreshTokenStore.revoke(refreshToken);
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
