package io.github.vpavic.oauth2.jwk;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link JwkGenerator}.
 *
 * @author Vedran Pavic
 */
public class JwkGeneratorTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void generateSigningRsaKey_noArguments_ShouldCreateKey() {
		RSAKey key = JwkGenerator.generateSigningRsaKey();
		assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(key.getKeyID()).hasSize(43);
		assertThat(key.size()).isEqualTo(2048);
	}

	@Test
	public void generateSigningEcKey_P256Curve_ShouldCreateKey() {
		ECKey key = JwkGenerator.generateSigningEcKey(Curve.P_256);
		assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(key.getKeyID()).hasSize(43);
		assertThat(key.size()).isEqualTo(256);
		assertThat(key.getCurve()).isEqualTo(Curve.P_256);
	}

	@Test
	public void generateSigningEcKey_nullCurve_shouldThrowException() {
		this.thrown.expect(NullPointerException.class);
		this.thrown.expectMessage("curve must not be null");

		JwkGenerator.generateSigningEcKey(null);
	}

	@Test
	public void generateEncryptionAesKey_noArguments_ShouldCreateKey() {
		OctetSequenceKey key = JwkGenerator.generateEncryptionAesKey();
		assertThat(key.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
		assertThat(key.getKeyID()).hasSize(43);
		assertThat(key.size()).isEqualTo(128);
	}

	@Test
	public void generateSigningHmacSha256Key_noArguments_ShouldCreateKey() {
		OctetSequenceKey key = JwkGenerator.generateSigningHmacSha256Key();
		assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(key.getKeyID()).isEqualTo("hmac");
		assertThat(key.size()).isEqualTo(256);
	}

	@Test
	public void generateSubjectEncryptionAesKey_noArguments_ShouldCreateKey() {
		OctetSequenceKey key = JwkGenerator.generateSubjectEncryptionAesKey();
		assertThat(key.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
		assertThat(key.getKeyID()).isEqualTo("subject-encrypt");
		assertThat(key.size()).isEqualTo(256);
	}

}
