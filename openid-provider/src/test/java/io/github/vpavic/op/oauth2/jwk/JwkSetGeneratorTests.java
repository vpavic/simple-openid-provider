package io.github.vpavic.op.oauth2.jwk;

import java.util.Iterator;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link JwkSetGenerator}.
 *
 * @author Vedran Pavic
 */
public class JwkSetGeneratorTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void generateRotatingKeys() {
		List<JWK> jwks = JwkSetGenerator.generateRotatingKeys();
		Iterator<JWK> jwkIterator = jwks.iterator();

		JWK jwk = jwkIterator.next();
		assertThat(jwk).isInstanceOf(RSAKey.class);
		assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(jwk.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
		assertThat(jwk.getKeyID()).hasSize(43);
		assertThat(jwk.size()).isEqualTo(2048);

		jwk = jwkIterator.next();
		assertThat(jwk).isInstanceOf(ECKey.class);
		assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(jwk.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
		assertThat(jwk.getKeyID()).hasSize(43);
		assertThat(jwk.size()).isEqualTo(256);

		jwk = jwkIterator.next();
		assertThat(jwk).isInstanceOf(ECKey.class);
		assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(jwk.getAlgorithm()).isEqualTo(JWSAlgorithm.ES384);
		assertThat(jwk.getKeyID()).hasSize(43);
		assertThat(jwk.size()).isEqualTo(384);

		jwk = jwkIterator.next();
		assertThat(jwk).isInstanceOf(ECKey.class);
		assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(jwk.getAlgorithm()).isEqualTo(JWSAlgorithm.ES512);
		assertThat(jwks.get(3).getKeyID()).hasSize(43);
		assertThat(jwks.get(3).size()).isEqualTo(521);

		jwk = jwkIterator.next();
		assertThat(jwk).isInstanceOf(OctetSequenceKey.class);
		assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
		assertThat(jwk.getKeyID()).hasSize(43);
		assertThat(jwk.size()).isEqualTo(128);
	}

	@Test
	public void generatePermanentKeys() {
		List<JWK> jwks = JwkSetGenerator.generatePermanentKeys();
		Iterator<JWK> jwkIterator = jwks.iterator();

		JWK jwk = jwkIterator.next();
		assertThat(jwk).isInstanceOf(OctetSequenceKey.class);
		assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(jwk.getKeyID()).isEqualTo("hmac");
		assertThat(jwk.size()).isEqualTo(256);

		jwk = jwkIterator.next();
		assertThat(jwk).isInstanceOf(OctetSequenceKey.class);
		assertThat(jwk.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
		assertThat(jwk.getKeyID()).isEqualTo("subject-encrypt");
		assertThat(jwk.size()).isEqualTo(256);
	}

}
