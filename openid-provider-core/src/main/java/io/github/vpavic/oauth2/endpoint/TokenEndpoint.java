package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import io.github.vpavic.oauth2.authentication.ClientRequestValidator;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.grant.GrantHandler;

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

	private final Map<Class<?>, GrantHandler> grantHandlers;

	private final ClientRequestValidator clientRequestValidator;

	public TokenEndpoint(Map<Class<?>, GrantHandler> grantHandlers, Issuer issuer, ClientRepository clientRepository) {
		Objects.requireNonNull(grantHandlers, "grantHandlers must not be null");
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		if (grantHandlers.isEmpty()) {
			throw new IllegalArgumentException("grantHandlers must not be empty");
		}
		this.grantHandlers = grantHandlers;
		this.clientRequestValidator = new ClientRequestValidator(issuer, clientRepository);
	}

	@PostMapping
	public void handleTokenRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		TokenResponse tokenResponse;

		try {
			TokenRequest tokenRequest = TokenRequest.parse(httpRequest);
			this.clientRequestValidator.validateRequest(tokenRequest);
			GrantHandler grantHandler = this.grantHandlers.get(tokenRequest.getAuthorizationGrant().getClass());

			if (grantHandler == null) {
				throw new GeneralException(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
			}

			Tokens tokens = grantHandler.grant(tokenRequest);
			tokenResponse = (tokens instanceof OIDCTokens) ? new OIDCTokenResponse((OIDCTokens) tokens)
					: new AccessTokenResponse(tokens);
		}
		catch (JOSEException e) {
			tokenResponse = new TokenErrorResponse(OAuth2Error.SERVER_ERROR);
		}
		catch (GeneralException e) {
			tokenResponse = new TokenErrorResponse(e.getErrorObject());
		}

		ServletUtils.applyHTTPResponse(tokenResponse.toHTTPResponse(), response);
	}

}
