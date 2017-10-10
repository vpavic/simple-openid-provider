package io.github.vpavic.op.oauth2.jwk;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Collection of JWK generators used by OpenID Provider.
 *
 * @author Vedran Pavic
 */
final class JwkGenerator {

	private static final String ALGORITHM_AES = "AES";

	private static final String ALGORITHM_EC = "EC";

	private static final String ALGORITHM_HMAC_SHA256 = "HmacSHA256";

	private static final String ALGORITHM_RSA = "RSA";

	private static final String KEY_ID_HMAC = "hmac";

	private static final String KEY_ID_SUBJECT_ENCRYPT = "subject-encrypt";

	private JwkGenerator() {

	}

	/**
	 * Generate a 2048 bit RSA signing key with key ID set to its SHA-256 JWK thumbprint.
	 * @return the generated JWK
	 */
	static RSAKey generateSigningRsaKey() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_RSA);
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

			// @formatter:off
			return new RSAKey.Builder(publicKey)
					.privateKey(privateKey)
					.keyUse(KeyUse.SIGNATURE)
					.keyIDFromThumbprint()
					.build();
			// @formatter:on
		}
		catch (NoSuchAlgorithmException | JOSEException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Generate an EC signing key with the specified algorithm and key ID set to its SHA-256 JWK thumbprint.
	 * @param curve the curve
	 * @return the generated JWK
	 */
	static ECKey generateSigningEcKey(final Curve curve) {
		Objects.requireNonNull(curve, "curve must not be null");

		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_EC);
			keyPairGenerator.initialize(curve.toECParameterSpec());
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
			ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

			// @formatter:off
			return new ECKey.Builder(curve, publicKey)
					.privateKey(privateKey)
					.keyUse(KeyUse.SIGNATURE)
					.keyIDFromThumbprint()
					.build();
			// @formatter:on
		}
		catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | JOSEException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Generate a 128 bit AES encryption key with key ID set to its SHA-256 JWK thumbprint.
	 * @return the generated JWK
	 */
	static OctetSequenceKey generateEncryptionAesKey() {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_AES);
			keyGenerator.init(128);
			SecretKey aesKey = keyGenerator.generateKey();

			// @formatter:off
			return new OctetSequenceKey.Builder(aesKey)
					.keyUse(KeyUse.ENCRYPTION)
					.keyIDFromThumbprint()
					.build();
			// @formatter:on
		}
		catch (NoSuchAlgorithmException | JOSEException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Generate a 256 bit HMAC SHA signing key with key ID "hmac".
	 * @return the generated JWK
	 */
	static OctetSequenceKey generateSigningHmacSha256Key() {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_HMAC_SHA256);
			SecretKey secretKey = keyGenerator.generateKey();

			// @formatter:off
			return new OctetSequenceKey.Builder(secretKey)
					.keyUse(KeyUse.SIGNATURE)
					.keyID(KEY_ID_HMAC)
					.build();
			// @formatter:on
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Generate a 256 bit AES encryption key intended for subject encryption with key ID "subject-encrypt".
	 * @return the generated JWK
	 */
	static OctetSequenceKey generateSubjectEncryptionAesKey() {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_AES);
			keyGenerator.init(256);
			SecretKey aesKey = keyGenerator.generateKey();

			// @formatter:off
			return new OctetSequenceKey.Builder(aesKey)
					.keyUse(KeyUse.ENCRYPTION)
					.keyID(KEY_ID_SUBJECT_ENCRYPT)
					.build();
			// @formatter:on
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

}
