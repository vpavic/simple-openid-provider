package io.github.vpavic.op.oauth2.endpoint;

import java.util.Objects;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.vpavic.op.oauth2.jwk.JwkSetStore;

/**
 * Endpoint that publishes server's public RSA keys as a JSON Web Key (JWK) set.
 *
 * @author Vedran Pavic
 */
@RestController
@RequestMapping(path = KeysEndpoint.PATH_MAPPING)
public class KeysEndpoint {

	public static final String PATH_MAPPING = "/oauth2/keys";

	private static final MediaType JWK_SET = MediaType.parseMediaType(JWKSet.MIME_TYPE);

	private final JwkSetStore jwkSetStore;

	public KeysEndpoint(JwkSetStore jwkSetStore) {
		Objects.requireNonNull(jwkSetStore, "jwkSetStore must not be null");

		this.jwkSetStore = jwkSetStore;
	}

	@GetMapping
	public ResponseEntity<String> getJwkSet() {
		JWKSet jwkSet = this.jwkSetStore.load();

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(JWK_SET)
				.body(jwkSet.toJSONObject().toJSONString());
		// @formatter:on
	}

}
