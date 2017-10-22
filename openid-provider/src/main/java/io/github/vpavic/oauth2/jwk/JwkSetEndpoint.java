package io.github.vpavic.oauth2.jwk;

import java.util.Objects;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Endpoint that publishes server's public RSA keys as a JSON Web Key (JWK) set.
 *
 * @author Vedran Pavic
 */
@Controller
@RequestMapping(path = JwkSetEndpoint.PATH_MAPPING)
public class JwkSetEndpoint {

	public static final String PATH_MAPPING = "/oauth2/keys";

	private static final MediaType JWK_SET = MediaType.parseMediaType(JWKSet.MIME_TYPE);

	private final JwkSetLoader jwkSetLoader;

	public JwkSetEndpoint(JwkSetLoader jwkSetLoader) {
		Objects.requireNonNull(jwkSetLoader, "jwkSetLoader must not be null");

		this.jwkSetLoader = jwkSetLoader;
	}

	@GetMapping
	public ResponseEntity<String> getJwkSet() {
		JWKSet jwkSet = this.jwkSetLoader.load();

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(JWK_SET)
				.body(jwkSet.toJSONObject().toJSONString());
		// @formatter:on
	}

}
