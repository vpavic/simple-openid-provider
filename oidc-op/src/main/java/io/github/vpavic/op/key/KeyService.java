package io.github.vpavic.op.key;

import java.util.List;

import com.nimbusds.jose.jwk.JWK;

public interface KeyService {

	JWK findDefault();

	List<JWK> findAll();

}
