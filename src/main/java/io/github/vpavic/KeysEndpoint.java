package io.github.vpavic;

import com.nimbusds.jose.jwk.JWKSet;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/keys")
public class KeysEndpoint {

	private final JWKSet jwkSet;

	public KeysEndpoint(@Value("classpath:jwks.json") Resource jwkSetResource) throws Exception {
		this.jwkSet = JWKSet.load(jwkSetResource.getFile());
	}

	@GetMapping(produces = JWKSet.MIME_TYPE)
	public JSONObject getKeys() {
		return this.jwkSet.toJSONObject();
	}

}
