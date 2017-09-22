package io.github.vpavic.op.oauth2.key;

import java.util.List;

import com.nimbusds.jose.jwk.JWK;

public interface KeyService {

	JWK findActive();

	List<JWK> findAll();

	void rotate();

}
