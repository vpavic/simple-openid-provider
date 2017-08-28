package io.github.vpavic.op.endpoint;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.nimbusds.jose.JWSHeader;
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
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.client.ClientType;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.Audience;
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
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import io.github.vpavic.op.client.ClientRepository;
import io.github.vpavic.op.code.AuthorizationCodeContext;
import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.config.OpenIdProviderProperties;
import io.github.vpavic.op.token.ClaimsMapper;
import io.github.vpavic.op.token.RefreshTokenContext;
import io.github.vpavic.op.token.RefreshTokenStore;
import io.github.vpavic.op.token.TokenService;

/**
 * OAuth 2.0 and OpenID Connect 1.0 compatible Token Endpoint implementation.
 *
 * @author Vedran Pavic
 * @see <a href="https://tools.ietf.org/html/rfc6749">RFC 6749: The OAuth 2.0 Authorization Framework</a>
 * @see <a href="https://tools.ietf.org/html/rfc7636">RFC 7636: Proof Key for Code Exchange by OAuth Public Clients</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
@RestController
@RequestMapping(path = TokenEndpoint.PATH_MAPPING)
public class TokenEndpoint {

	public static final String PATH_MAPPING = "/oauth2/token";

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	private final AuthenticationManager authenticationManager;

	private final RefreshTokenStore refreshTokenStore;

	private final ClaimsMapper claimsMapper;

	public TokenEndpoint(OpenIdProviderProperties properties, ClientRepository clientRepository,
			AuthorizationCodeService authorizationCodeService, TokenService tokenService,
			AuthenticationManager authenticationManager, RefreshTokenStore refreshTokenStore,
			ClaimsMapper claimsMapper) {
		this.properties = properties;
		this.clientRepository = Objects.requireNonNull(clientRepository);
		this.authorizationCodeService = Objects.requireNonNull(authorizationCodeService);
		this.tokenService = Objects.requireNonNull(tokenService);
		this.authenticationManager = Objects.requireNonNull(authenticationManager);
		this.refreshTokenStore = Objects.requireNonNull(refreshTokenStore);
		this.claimsMapper = Objects.requireNonNull(claimsMapper);
	}

	@PostMapping
	public JSONObject handleTokenRequest(ServletWebRequest request) throws Exception {
		TokenRequest tokenRequest = resolveTokenRequest(request);

		AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();

		AccessTokenResponse tokenResponse;

		// Authorization Code Grant Type
		if (authorizationGrant instanceof AuthorizationCodeGrant) {
			AuthorizationCodeGrant authorizationCodeGrant = (AuthorizationCodeGrant) authorizationGrant;
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
			ClientID clientID = context.getClientID();
			Scope scope = context.getScope();
			Instant authenticationTime = context.getAuthenticationTime();
			String sessionId = context.getSessionId();
			Nonce nonce = context.getNonce();

			AccessToken accessToken = this.tokenService.createAccessToken(principal, clientID, scope,
					this.claimsMapper);
			RefreshToken refreshToken = null;

			if (scope.contains(OIDCScopeValue.OFFLINE_ACCESS)) {
				refreshToken = this.tokenService.createRefreshToken(principal, clientID, scope);
			}

			JWT idToken = this.tokenService.createIdToken(principal, clientID, scope, authenticationTime, sessionId,
					nonce, accessToken, null, null);
			OIDCTokens tokens = new OIDCTokens(idToken.serialize(), accessToken, refreshToken);

			tokenResponse = new OIDCTokenResponse(tokens);
		}
		// Resource Owner Password Credentials Grant Type
		else if (authorizationGrant instanceof ResourceOwnerPasswordCredentialsGrant) {
			ResourceOwnerPasswordCredentialsGrant passwordCredentialsGrant = (ResourceOwnerPasswordCredentialsGrant) authorizationGrant;
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
			ClientID clientID = tokenRequest.getClientAuthentication().getClientID();
			Scope scope = tokenRequest.getScope();

			AccessToken accessToken = this.tokenService.createAccessToken(principal, clientID, scope,
					this.claimsMapper);
			RefreshToken refreshToken = null;

			if (scope.contains(OIDCScopeValue.OFFLINE_ACCESS)) {
				refreshToken = this.tokenService.createRefreshToken(principal, clientID, scope);
			}

			Tokens tokens = new Tokens(accessToken, refreshToken);

			tokenResponse = new AccessTokenResponse(tokens);
		}
		// Client Credentials Grant Type
		else if (authorizationGrant instanceof ClientCredentialsGrant) {
			ClientID clientID = tokenRequest.getClientAuthentication().getClientID();
			String principal = clientID.getValue();
			Scope scope = tokenRequest.getScope();

			AccessToken accessToken = this.tokenService.createAccessToken(principal, clientID, scope, null);
			Tokens tokens = new Tokens(accessToken, null);

			tokenResponse = new AccessTokenResponse(tokens);
		}
		// Refresh Token Grant Type
		else if (authorizationGrant instanceof RefreshTokenGrant) {
			RefreshTokenGrant refreshTokenGrant = (RefreshTokenGrant) authorizationGrant;
			RefreshToken refreshToken = refreshTokenGrant.getRefreshToken();
			RefreshTokenContext context = this.refreshTokenStore.load(refreshToken);
			String principal = context.getPrincipal();
			ClientID clientID = context.getClientID();
			Scope scope = context.getScope();

			AccessToken accessToken = this.tokenService.createAccessToken(principal, clientID, scope,
					this.claimsMapper);
			Tokens tokens = new Tokens(accessToken, null);

			tokenResponse = new AccessTokenResponse(tokens);
		}
		else {
			throw new GeneralException(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		}

		return tokenResponse.toJSONObject();
	}

	private TokenRequest resolveTokenRequest(ServletWebRequest request) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request.getRequest());
		TokenRequest tokenRequest = TokenRequest.parse(httpRequest);
		validateRequest(tokenRequest);

		return tokenRequest;
	}

	private void validateRequest(TokenRequest request) throws Exception {
		ClientAuthentication clientAuthentication = request.getClientAuthentication();

		OIDCClientInformation client = this.clientRepository.findByClientId(
				(clientAuthentication != null) ? clientAuthentication.getClientID() : request.getClientID());

		if (client == null) {
			throw InvalidClientException.BAD_ID;
		}

		if (client.inferClientType() == ClientType.CONFIDENTIAL) {
			if (clientAuthentication == null) {
				throw InvalidClientException.BAD_SECRET;
			}

			ClientAuthenticationVerifier<OIDCClientInformation> verifier = new ClientAuthenticationVerifier<>(
					new ClientInformationCredentialsSelector(), null,
					Collections.singleton(new Audience(this.properties.getIssuer())));

			Context<OIDCClientInformation> context = new Context<>();
			context.set(client);
			verifier.verify(clientAuthentication, null, context);
		}
	}

	@ExceptionHandler(GeneralException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public JSONObject handleParseException(GeneralException e) {
		ErrorObject error = e.getErrorObject();

		if (error == null) {
			error = OAuth2Error.INVALID_REQUEST.setDescription(e.getMessage());
		}

		return new TokenErrorResponse(error).toJSONObject();
	}

	private static class ClientInformationCredentialsSelector
			implements ClientCredentialsSelector<OIDCClientInformation> {

		@Override
		public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod,
				Context<OIDCClientInformation> context) throws InvalidClientException {
			OIDCClientInformation client = context.get();
			ClientAuthenticationMethod configuredAuthMethod = client.getOIDCMetadata().getTokenEndpointAuthMethod();

			if (configuredAuthMethod != null && !configuredAuthMethod.equals(authMethod)) {
				throw InvalidClientException.NOT_REGISTERED_FOR_AUTH_METHOD;
			}

			return Collections.singletonList(client.getSecret());
		}

		@Override
		public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID,
				ClientAuthenticationMethod authMethod, JWSHeader jwsHeader, boolean forceRefresh,
				Context<OIDCClientInformation> context) throws InvalidClientException {
			return Collections.emptyList();
		}

	}

}
