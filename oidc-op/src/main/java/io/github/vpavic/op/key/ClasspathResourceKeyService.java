package io.github.vpavic.op.key;

import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

@Service
public class ClasspathResourceKeyService implements KeyService {

	private static final String DEFAULT_KID = "nimbus-oidc-provider";

	private final JWKSet jwkSet;

	public ClasspathResourceKeyService(@Value("classpath:jwks.json") Resource jwkSetResource) throws Exception {
		this.jwkSet = JWKSet.load(jwkSetResource.getFile());
	}

	@Override
	public JWK generateKey(String kid) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void save(JWK jwk) {
		throw new UnsupportedOperationException();
	}

	@Override
	public JWK findByKeyId(String kid) {
		return this.jwkSet.getKeyByKeyId(kid);
	}

	@Override
	public JWK findDefault() {
		return this.jwkSet.getKeyByKeyId(DEFAULT_KID);
	}

	@Override
	public List<JWK> findAll() {
		return this.jwkSet.getKeys();
	}

}
