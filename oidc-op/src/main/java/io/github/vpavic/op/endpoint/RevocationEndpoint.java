package io.github.vpavic.op.endpoint;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.TokenRevocationRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import io.github.vpavic.op.client.ClientRequestValidator;
import io.github.vpavic.op.token.RefreshTokenStore;

/**
 * OAuth 2.0 compatible Token Revocation Endpoint implementation.
 *
 * @author Vedran Pavic
 * @see <a href="https://tools.ietf.org/html/rfc6749">RFC 6749: The OAuth 2.0 Authorization Framework</a>
 * @see <a href="https://tools.ietf.org/html/rfc7009">RFC 7009: OAuth 2.0 Token Revocation</a>
 */
@RestController
@RequestMapping(path = RevocationEndpoint.PATH_MAPPING)
public class RevocationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/revoke";

	private final ClientRequestValidator clientRequestValidator;

	private final RefreshTokenStore refreshTokenStore;

	public RevocationEndpoint(ClientRequestValidator clientRequestValidator, RefreshTokenStore refreshTokenStore) {
		this.clientRequestValidator = Objects.requireNonNull(clientRequestValidator);
		this.refreshTokenStore = Objects.requireNonNull(refreshTokenStore);
	}

	@PostMapping
	public void handleRevocationRequest(ServletWebRequest request) throws Exception {
		TokenRevocationRequest revocationRequest = resolveRevocationRequest(request);
		Token token = revocationRequest.getToken();
		RefreshToken refreshToken;

		if (token instanceof RefreshToken) {
			refreshToken = (RefreshToken) token;
		}
		else {
			refreshToken = new RefreshToken(token.getValue());
		}

		this.refreshTokenStore.revoke(refreshToken);
	}

	private TokenRevocationRequest resolveRevocationRequest(ServletWebRequest request) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request.getRequest());
		TokenRevocationRequest revocationRequest = TokenRevocationRequest.parse(httpRequest);
		this.clientRequestValidator.validateRequest(revocationRequest);

		return revocationRequest;
	}

}
