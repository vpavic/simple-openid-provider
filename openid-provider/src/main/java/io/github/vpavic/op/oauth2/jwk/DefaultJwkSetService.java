package io.github.vpavic.op.oauth2.jwk;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DefaultJwkSetService implements JwkSetService, ApplicationRunner {

	private final JwkSetStore jwkSetStore;

	public DefaultJwkSetService(JwkSetStore jwkSetStore) {
		Objects.requireNonNull(jwkSetStore, "jwkSetStore must not be null");

		this.jwkSetStore = jwkSetStore;
	}

	@Override
	@Transactional
	public void rotate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		JWKSet jwkSet = this.jwkSetStore.load();
		List<JWK> keys = new LinkedList<>();
		keys.addAll(generateRotatingKeys());
		keys.addAll(jwkSet.getKeys());
		jwkSet = new JWKSet(keys);
		this.jwkSetStore.save(jwkSet);
	}

	@Override
	public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
		JWKSet jwkSet = this.jwkSetStore.load();

		return jwkSelector.select(jwkSet);
	}

	@Override
	@Transactional
	public void run(ApplicationArguments args) throws Exception {
		JWKSet jwkSet = this.jwkSetStore.load();

		if (jwkSet.getKeys().isEmpty()) {
			List<JWK> keys = new LinkedList<>();
			keys.addAll(generateRotatingKeys());
			keys.addAll(generatePermanentKeys());
			jwkSet = new JWKSet(keys);
			this.jwkSetStore.save(jwkSet);
		}
		else {
			// TODO validate keys
		}
	}

	private List<JWK> generateRotatingKeys() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		List<JWK> keys = new LinkedList<>();
		keys.add(generateSigningRsaKey(JWSAlgorithm.RS256, generateKeyId()));
		keys.add(generateSigningEcKey(JWSAlgorithm.ES256, generateKeyId()));
		keys.add(generateSigningEcKey(JWSAlgorithm.ES384, generateKeyId()));
		keys.add(generateSigningEcKey(JWSAlgorithm.ES512, generateKeyId()));
		keys.add(generateEncryptionAesKey(generateKeyId()));

		return keys;
	}

	private List<JWK> generatePermanentKeys() throws NoSuchAlgorithmException {
		List<JWK> keys = new LinkedList<>();
		keys.add(generateHmacSha256Key());
		keys.add(generateSubjectEncryptionKey());

		return keys;
	}

	private static String generateKeyId() {
		return UUID.randomUUID().toString();
	}

	private static RSAKey generateSigningRsaKey(final JWSAlgorithm algorithm, final String kid)
			throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		// @formatter:off
		return new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyUse(KeyUse.SIGNATURE)
				.algorithm(algorithm)
				.keyID(kid)
				.build();
		// @formatter:on
	}

	private static ECKey generateSigningEcKey(final JWSAlgorithm algorithm, final String kid)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		Curve curve = Curve.forJWSAlgorithm(algorithm).iterator().next();
		keyPairGenerator.initialize(curve.toECParameterSpec());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		// @formatter:off
		return new ECKey.Builder(curve, publicKey)
				.privateKey(privateKey)
				.keyUse(KeyUse.SIGNATURE)
				.algorithm(algorithm)
				.keyID(kid)
				.build();
		// @formatter:on
	}

	private static OctetSequenceKey generateEncryptionAesKey(final String kid) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey aesKey = keyGenerator.generateKey();

		// @formatter:off
		return new OctetSequenceKey.Builder(aesKey)
				.keyUse(KeyUse.ENCRYPTION)
				.keyID(kid)
				.build();
		// @formatter:on
	}

	private static OctetSequenceKey generateHmacSha256Key() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSha256");
		SecretKey secretKey = keyGenerator.generateKey();

		// @formatter:off
		return new OctetSequenceKey.Builder(secretKey)
				.keyUse(KeyUse.SIGNATURE)
				.keyID("hmac")
				.build();
		// @formatter:on
	}

	private static OctetSequenceKey generateSubjectEncryptionKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		SecretKey aesKey = keyGenerator.generateKey();

		// @formatter:off
		return new OctetSequenceKey.Builder(aesKey)
				.keyUse(KeyUse.ENCRYPTION)
				.keyID("subject-encrypt")
				.build();
		// @formatter:on
	}

}
