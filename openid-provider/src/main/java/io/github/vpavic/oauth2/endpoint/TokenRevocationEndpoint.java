package io.github.vpavic.oauth2.endpoint;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenRevocationRequest;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import io.github.vpavic.oauth2.authentication.ClientRequestValidator;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.token.RefreshTokenStore;

/**
 * OAuth 2.0 compatible Token Revocation Endpoint implementation.
 *
 * @author Vedran Pavic
 * @see <a href="https://tools.ietf.org/html/rfc6749">RFC 6749: The OAuth 2.0 Authorization Framework</a>
 * @see <a href="https://tools.ietf.org/html/rfc7009">RFC 7009: OAuth 2.0 Token Revocation</a>
 */
@RequestMapping(path = TokenRevocationEndpoint.PATH_MAPPING)
public class TokenRevocationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/revoke";

	private final RefreshTokenStore refreshTokenStore;

	private final ClientRequestValidator clientRequestValidator;

	public TokenRevocationEndpoint(Issuer issuer, ClientRepository clientRepository,
			RefreshTokenStore refreshTokenStore) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(refreshTokenStore, "refreshTokenStore must not be null");

		this.refreshTokenStore = refreshTokenStore;
		this.clientRequestValidator = new ClientRequestValidator(issuer, clientRepository);
	}

	@PostMapping
	public ResponseEntity<Void> handleRevocationRequest(HTTPRequest httpRequest) throws Exception {
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

		// @formatter:off
		return ResponseEntity.ok()
				.build();
		// @formatter:on
	}

	@ExceptionHandler(InvalidClientException.class)
	public ResponseEntity<String> handleInvalidClientException(InvalidClientException e) {
		ErrorObject error = e.getErrorObject();

		// @formatter:off
		return ResponseEntity.status(error.getHTTPStatusCode())
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(error.toJSONObject().toJSONString());
		// @formatter:on
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<Void> handleException() {
		// @formatter:off
		return ResponseEntity.ok()
				.build();
		// @formatter:on
	}

}
