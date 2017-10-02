package io.github.vpavic.op.oauth2.jwk;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class JwkSetInitializer implements ApplicationRunner {

	private final JwkSetStore jwkSetStore;

	public JwkSetInitializer(JwkSetStore jwkSetStore) {
		Objects.requireNonNull(jwkSetStore, "jwkSetStore must not be null");

		this.jwkSetStore = jwkSetStore;
	}

	@Override
	@Transactional
	public void run(ApplicationArguments args) throws Exception {
		JWKSet jwkSet = this.jwkSetStore.load();

		if (jwkSet.getKeys().isEmpty()) {
			List<JWK> keys = new LinkedList<>();
			keys.addAll(JwkSetGenerator.generateRotatingKeys());
			keys.addAll(JwkSetGenerator.generatePermanentKeys());
			jwkSet = new JWKSet(keys);
			this.jwkSetStore.save(jwkSet);
		}
		else {
			// TODO validate keys
		}
	}

}
