package io.github.vpavic.op.key;

import java.util.List;

import com.nimbusds.jose.jwk.JWK;

public interface KeyService {

	JWK generateKey(String kid);

	void save(JWK jwk);

	JWK findByKeyId(String kid);

	JWK findDefault();

	List<JWK> findAll();

}
