package io.github.vpavic.oauth2.endpoint;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenRevocationRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import io.github.vpavic.oauth2.authentication.ClientRequestValidator;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.grant.GrantHandler;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenStore;

/**
 * OAuth 2.0 and OpenID Connect 1.0 compatible Token Endpoint implementation.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749">RFC 6749: The OAuth 2.0 Authorization Framework</a>
 * @see <a href="https://tools.ietf.org/html/rfc7009">RFC 7009: OAuth 2.0 Token Revocation</a>
 * @see <a href="https://tools.ietf.org/html/rfc7636">RFC 7636: Proof Key for Code Exchange by OAuth Public Clients</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
public class TokenHandler {

	private final Map<Class<?>, GrantHandler> grantHandlers;

	private final RefreshTokenStore refreshTokenStore;

	private final ClientRequestValidator clientRequestValidator;

	public TokenHandler(List<GrantHandler> grantHandlers, RefreshTokenStore refreshTokenStore, Issuer issuer,
			ClientRepository clientRepository) {
		Objects.requireNonNull(grantHandlers, "grantHandlers must not be null");
		Objects.requireNonNull(refreshTokenStore, "refreshTokenStore must not be null");
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		if (grantHandlers.isEmpty()) {
			throw new IllegalArgumentException("grantHandlers must not be empty");
		}
		this.grantHandlers = grantHandlers.stream().collect(Collectors.toMap(GrantHandler::grantType, entry -> entry));
		this.refreshTokenStore = refreshTokenStore;
		this.clientRequestValidator = new ClientRequestValidator(issuer, clientRepository);
	}

	public HTTPResponse handleTokenRequest(HTTPRequest httpRequest) {
		HTTPResponse httpResponse;

		try {
			TokenRequest tokenRequest = TokenRequest.parse(httpRequest);
			this.clientRequestValidator.validateRequest(tokenRequest);
			GrantHandler grantHandler = this.grantHandlers.get(tokenRequest.getAuthorizationGrant().getClass());

			if (grantHandler == null) {
				throw new GeneralException(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
			}

			Tokens tokens = grantHandler.grant(tokenRequest);
			AccessTokenResponse tokenResponse = (tokens instanceof OIDCTokens)
					? new OIDCTokenResponse((OIDCTokens) tokens)
					: new AccessTokenResponse(tokens);
			httpResponse = tokenResponse.toHTTPResponse();
		}
		catch (JOSEException e) {
			TokenErrorResponse tokenResponse = new TokenErrorResponse(OAuth2Error.SERVER_ERROR);
			httpResponse = tokenResponse.toHTTPResponse();
		}
		catch (GeneralException e) {
			ErrorObject error = Optional.ofNullable(e.getErrorObject()).orElse(OAuth2Error.INVALID_REQUEST);
			TokenErrorResponse tokenResponse = new TokenErrorResponse(error);
			httpResponse = tokenResponse.toHTTPResponse();
		}

		return httpResponse;
	}

	public HTTPResponse handleTokenRevocationRequest(HTTPRequest httpRequest) {
		HTTPResponse httpResponse;

		try {
			TokenRevocationRequest revocationRequest = TokenRevocationRequest.parse(httpRequest);
			this.clientRequestValidator.validateRequest(revocationRequest);
			Token token = revocationRequest.getToken();
			RefreshToken refreshToken;

			if (token instanceof RefreshToken) {
				refreshToken = (RefreshToken) token;
			}
			else {
				refreshToken = new RefreshToken(token.getValue());
			}

			this.refreshTokenStore.revoke(refreshToken);

			httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		}
		catch (JOSEException e) {
			httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		}
		catch (GeneralException e) {
			TokenErrorResponse tokenResponse = new TokenErrorResponse(e.getErrorObject());
			httpResponse = tokenResponse.toHTTPResponse();
		}

		return httpResponse;
	}

}
