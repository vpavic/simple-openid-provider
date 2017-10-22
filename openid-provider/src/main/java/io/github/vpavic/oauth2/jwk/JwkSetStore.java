package io.github.vpavic.oauth2.jwk;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * {@link JWKSet} store.
 *
 * @author Vedran Pavic
 */
public interface JwkSetStore extends JwkSetLoader {

	/**
	 * Rotate JWKs, keeping the decommissioned JWKs for the configured period of time
	 */
	void rotate();

}
