package io.github.vpavic.oauth2.endpoint;

import java.util.Map;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
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

	@PostMapping(produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<String> handleTokenRequest(HTTPRequest httpRequest) throws Exception {
		TokenRequest tokenRequest = TokenRequest.parse(httpRequest);
		this.clientRequestValidator.validateRequest(tokenRequest);
		AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();
		GrantHandler grantHandler = this.grantHandlers.get(authorizationGrant.getClass());

		if (grantHandler == null) {
			throw new GeneralException(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		}

		Tokens tokens = grantHandler.grant(authorizationGrant, tokenRequest.getScope(),
				tokenRequest.getClientAuthentication());
		AccessTokenResponse tokenResponse = (tokens instanceof OIDCTokens) ? new OIDCTokenResponse((OIDCTokens) tokens)
				: new AccessTokenResponse(tokens);

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(tokenResponse.toJSONObject().toJSONString());
		// @formatter:on
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
