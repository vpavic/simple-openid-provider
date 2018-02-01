package io.github.vpavic.oauth2.endpoint;

import java.util.Objects;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import io.github.vpavic.oauth2.jwk.JwkSetLoader;

/**
 * Endpoint that publishes server's public RSA keys as a JSON Web Key (JWK) set.
 */
public class JwkSetHandler {

	private final JwkSetLoader jwkSetLoader;

	public JwkSetHandler(JwkSetLoader jwkSetLoader) {
		Objects.requireNonNull(jwkSetLoader, "jwkSetLoader must not be null");
		this.jwkSetLoader = jwkSetLoader;
	}

	public HTTPResponse getJwkSet() {
		HTTPResponse httpResponse;
		try {
			JWKSet jwkSet = this.jwkSetLoader.load();

			httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
			httpResponse.setContentType(JWKSet.MIME_TYPE);
			httpResponse.setContent(jwkSet.toJSONObject().toJSONString());
		}
		catch (Exception e) {
			httpResponse = new HTTPResponse(HTTPResponse.SC_SERVER_ERROR);
		}

		return httpResponse;
	}

}
