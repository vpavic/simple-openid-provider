package io.github.vpavic.oauth2.jwk;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * {@link JWKSet} loader.
 */
public interface JwkSetLoader {

	/**
	 * Load JWK set.
	 * @return the JWK set
	 */
	JWKSet load();

}
