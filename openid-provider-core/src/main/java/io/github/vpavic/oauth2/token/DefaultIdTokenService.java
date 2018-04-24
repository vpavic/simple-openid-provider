package io.github.vpavic.oauth2.token;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeyException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionFactory;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.AuthorizedParty;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.github.vpavic.oauth2.claim.ClaimHelper;
import io.github.vpavic.oauth2.claim.ClaimSource;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;

public class DefaultIdTokenService implements IdTokenService {

	private static final Scope SCOPE_OPENID = new Scope(OIDCScopeValue.OPENID);

	private static final BouncyCastleProvider jcaProvider = new BouncyCastleProvider();

	private final Issuer issuer;

	private final JwkSetLoader jwkSetLoader;

	private final ClaimSource claimSource;

	private Duration idTokenLifetime = Duration.ofMinutes(15);

	private Map<Scope.Value, List<String>> scopeClaims = new HashMap<>();

	private boolean frontChannelLogoutEnabled;

	public DefaultIdTokenService(Issuer issuer, JwkSetLoader jwkSetLoader, ClaimSource claimSource) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(jwkSetLoader, "jwkSetLoader must not be null");
		Objects.requireNonNull(claimSource, "claimSource must not be null");
		this.issuer = issuer;
		this.jwkSetLoader = jwkSetLoader;
		this.claimSource = claimSource;
	}

	@Override
	public JWT createIdToken(IdTokenRequest idTokenRequest) {
		Instant now = Instant.now();
		Subject subject = idTokenRequest.getSubject();
		OIDCClientInformation client = idTokenRequest.getClient();
		ClientID clientId = client.getID();
		JWSAlgorithm algorithm = client.getOIDCMetadata().getIDTokenJWSAlg();
		UserInfo userInfo = this.claimSource.load(subject, resolveClaims(idTokenRequest));
		List<Audience> audience = Audience.create(clientId.getValue());
		Date expirationTime = Date.from(now.plus(this.idTokenLifetime));
		Date issueTime = Date.from(now);

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(this.issuer, userInfo.getSubject(), audience, expirationTime,
				issueTime);
		claimsSet.setAuthenticationTime(Date.from(idTokenRequest.getAuthenticationTime()));
		claimsSet.setNonce(idTokenRequest.getNonce());
		claimsSet.setACR(idTokenRequest.getAcr());
		claimsSet.setAMR(idTokenRequest.getAmrs());
		claimsSet.setAuthorizedParty(new AuthorizedParty(clientId.getValue()));
		claimsSet.putAll(userInfo);

		if (this.frontChannelLogoutEnabled) {
			SessionID sessionId = idTokenRequest.getSessionId();
			claimsSet.setSessionID(sessionId);
		}

		AccessToken accessToken = idTokenRequest.getAccessToken();

		if (accessToken != null) {
			AccessTokenHash accessTokenHash = AccessTokenHash.compute(accessToken, algorithm);
			claimsSet.setAccessTokenHash(accessTokenHash);
		}

		AuthorizationCode code = idTokenRequest.getCode();

		if (code != null) {
			CodeHash codeHash = CodeHash.compute(code, algorithm);
			claimsSet.setCodeHash(codeHash);
		}

		try {
			JWTAssertionDetails details = JWTAssertionDetails.parse(claimsSet.toJWTClaimsSet());

			if (JWSAlgorithm.Family.HMAC_SHA.contains(algorithm)) {
				Secret secret = client.getSecret();

				return JWTAssertionFactory.create(details, algorithm, secret);
			}
			else if (JWSAlgorithm.Family.RSA.contains(algorithm)) {
				RSAKey rsaKey = (RSAKey) resolveJwk(algorithm);

				return JWTAssertionFactory.create(details, algorithm, rsaKey.toRSAPrivateKey(), rsaKey.getKeyID(),
						jcaProvider);
			}
			else if (JWSAlgorithm.Family.EC.contains(algorithm)) {
				ECKey ecKey = (ECKey) resolveJwk(algorithm);

				return JWTAssertionFactory.create(details, algorithm, ecKey.toECPrivateKey(), ecKey.getKeyID(),
						jcaProvider);
			}

			throw new KeyException("Unsupported algorithm: " + algorithm);
		}
		catch (ParseException | JOSEException e) {
			throw new RuntimeException(e);
		}
	}

	public void setIdTokenLifetime(Duration idTokenLifetime) {
		this.idTokenLifetime = idTokenLifetime;
	}

	public void setScopeClaims(Map<Scope.Value, List<String>> scopeClaims) {
		this.scopeClaims = scopeClaims;
	}

	public void setFrontChannelLogoutEnabled(boolean frontChannelLogoutEnabled) {
		this.frontChannelLogoutEnabled = frontChannelLogoutEnabled;
	}

	private Set<String> resolveClaims(IdTokenRequest idTokenRequest) {
		Scope scope = (idTokenRequest.getAccessToken() != null) ? SCOPE_OPENID : idTokenRequest.getScope();

		return ClaimHelper.resolveClaims(scope, this.scopeClaims);
	}

	private JWK resolveJwk(JWSAlgorithm algorithm) {
		// @formatter:off
		JWKMatcher jwkMatcher = new JWKMatcher.Builder()
				.keyType(KeyType.forAlgorithm(algorithm))
				.keyUse(KeyUse.SIGNATURE)
				.build();
		// @formatter:on

		JWKSelector jwkSelector = new JWKSelector(jwkMatcher);
		JWKSet jwkSet = this.jwkSetLoader.load();
		List<JWK> keys = jwkSelector.select(jwkSet);

		return keys.iterator().next();
	}

}
