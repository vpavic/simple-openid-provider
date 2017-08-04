package io.github.vpavic.op.endpoint;

import java.util.List;
import java.util.Objects;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import net.minidev.json.JSONObject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.vpavic.op.key.KeyService;

/**
 * Endpoint that publishes server's public RSA keys as a JSON Web Key (JWK) set.
 *
 * @author Vedran Pavic
 */
@RestController
@RequestMapping(path = "/keys")
public class KeysEndpoint {

	private final KeyService keyService;

	public KeysEndpoint(KeyService keyService) {
		this.keyService = Objects.requireNonNull(keyService);
	}

	@GetMapping(produces = JWKSet.MIME_TYPE)
	public JSONObject getKeys() {
		List<JWK> jwks = this.keyService.findAll();
		return new JWKSet(jwks).toJSONObject();
	}

}
