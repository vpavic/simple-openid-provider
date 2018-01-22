package io.github.vpavic.oauth2.endpoint;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRevocationRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;

import io.github.vpavic.oauth2.authentication.ClientRequestValidator;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenStore;

/**
 * OAuth 2.0 compatible Token Revocation Endpoint implementation.
 *
 * @author Vedran Pavic
 * @see <a href="https://tools.ietf.org/html/rfc6749">RFC 6749: The OAuth 2.0 Authorization Framework</a>
 * @see <a href="https://tools.ietf.org/html/rfc7009">RFC 7009: OAuth 2.0 Token Revocation</a>
 */
public class TokenRevocationHandler {

	private final RefreshTokenStore refreshTokenStore;

	private final ClientRequestValidator clientRequestValidator;

	public TokenRevocationHandler(Issuer issuer, ClientRepository clientRepository,
			RefreshTokenStore refreshTokenStore) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(refreshTokenStore, "refreshTokenStore must not be null");
		this.refreshTokenStore = refreshTokenStore;
		this.clientRequestValidator = new ClientRequestValidator(issuer, clientRepository);
	}

	public void handleRevocationRequest(HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);

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

			response.setStatus(HttpServletResponse.SC_OK);
		}
		catch (JOSEException e) {
			response.setStatus(HttpServletResponse.SC_OK);
		}
		catch (GeneralException e) {
			TokenErrorResponse tokenResponse = new TokenErrorResponse(e.getErrorObject());
			ServletUtils.applyHTTPResponse(tokenResponse.toHTTPResponse(), response);
		}
	}

}
