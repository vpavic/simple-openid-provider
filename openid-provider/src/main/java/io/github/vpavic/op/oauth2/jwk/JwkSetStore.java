package io.github.vpavic.op.oauth2.jwk;

import com.nimbusds.jose.jwk.JWKSet;

public interface JwkSetStore {

	JWKSet load();

	void save(JWKSet jwkSet);

}
