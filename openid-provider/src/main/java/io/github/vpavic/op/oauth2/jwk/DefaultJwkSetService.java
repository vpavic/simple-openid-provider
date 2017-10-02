package io.github.vpavic.op.oauth2.jwk;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DefaultJwkSetService implements JwkSetService {

	private final JwkSetStore jwkSetStore;

	public DefaultJwkSetService(JwkSetStore jwkSetStore) {
		Objects.requireNonNull(jwkSetStore, "jwkSetStore must not be null");

		this.jwkSetStore = jwkSetStore;
	}

	@Override
	@Transactional
	public void rotate() {
		JWKSet jwkSet = this.jwkSetStore.load();
		List<JWK> keys = new LinkedList<>();
		keys.addAll(JwkSetGenerator.generateRotatingKeys());
		keys.addAll(jwkSet.getKeys());
		jwkSet = new JWKSet(keys);
		this.jwkSetStore.save(jwkSet);
	}

	@Override
	public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
		JWKSet jwkSet = this.jwkSetStore.load();

		return jwkSelector.select(jwkSet);
	}

}
