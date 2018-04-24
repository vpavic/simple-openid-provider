package io.github.vpavic.oauth2.token;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

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
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionFactory;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.github.vpavic.oauth2.claim.ClaimSource;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;

public class JwtAccessTokenService implements AccessTokenService {

	private static final BouncyCastleProvider jcaProvider = new BouncyCastleProvider();

	private final Issuer issuer;

	private final JwkSetLoader jwkSetLoader;

	private final ClaimSource claimSource;

	private Map<Scope.Value, String> resourceScopes = new HashMap<>();

	private Duration accessTokenLifetime = Duration.ofMinutes(10);

	private JWSAlgorithm accessTokenJwsAlgorithm = JWSAlgorithm.RS256;

	private String accessTokenScopeClaim = "scp";

	private String accessTokenClientIdClaim = "cid";

	private List<String> accessTokenSubjectClaims = new ArrayList<>();

	public JwtAccessTokenService(Issuer issuer, JwkSetLoader jwkSetLoader, ClaimSource claimSource) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(jwkSetLoader, "jwkSetLoader must not be null");
		Objects.requireNonNull(claimSource, "claimSource must not be null");
		this.issuer = issuer;
		this.jwkSetLoader = jwkSetLoader;
		this.claimSource = claimSource;
	}

	@Override
	public AccessToken createAccessToken(AccessTokenRequest accessTokenRequest) {
		Instant now = Instant.now();

		Subject subject = accessTokenRequest.getSubject();
		OIDCClientInformation client = accessTokenRequest.getClient();
		Scope scope = accessTokenRequest.getScope();

		Set<Audience> audiences = new LinkedHashSet<>();
		audiences.add(new Audience(this.issuer));

		for (Scope.Value value : scope) {
			String resource = this.resourceScopes.get(value);

			if (resource != null) {
				audiences.add(new Audience(resource));
			}
		}

		Date expirationTime = Date.from(now.plus(this.accessTokenLifetime));
		Date issueTime = Date.from(now);
		JWTID jwtId = new JWTID(UUID.randomUUID().toString());
		UserInfo userInfo = this.claimSource.load(subject, new HashSet<>(this.accessTokenSubjectClaims));
		userInfo.setClaim(this.accessTokenScopeClaim, scope);
		userInfo.setClaim(this.accessTokenClientIdClaim, client.getID());

		try {
			JWTAssertionDetails details = new JWTAssertionDetails(this.issuer, userInfo.getSubject(),
					new ArrayList<>(audiences), expirationTime, issueTime, issueTime, jwtId, userInfo.toJSONObject());
			SignedJWT accessToken;

			if (JWSAlgorithm.Family.HMAC_SHA.contains(this.accessTokenJwsAlgorithm)) {
				Secret secret = client.getSecret();

				accessToken = JWTAssertionFactory.create(details, this.accessTokenJwsAlgorithm, secret);
			}
			else if (JWSAlgorithm.Family.RSA.contains(this.accessTokenJwsAlgorithm)) {
				RSAKey rsaKey = (RSAKey) resolveJwk(this.accessTokenJwsAlgorithm);

				accessToken = JWTAssertionFactory.create(details, this.accessTokenJwsAlgorithm,
						rsaKey.toRSAPrivateKey(), rsaKey.getKeyID(), jcaProvider);
			}
			else if (JWSAlgorithm.Family.EC.contains(this.accessTokenJwsAlgorithm)) {
				ECKey ecKey = (ECKey) resolveJwk(this.accessTokenJwsAlgorithm);

				accessToken = JWTAssertionFactory.create(details, this.accessTokenJwsAlgorithm, ecKey.toECPrivateKey(),
						ecKey.getKeyID(), jcaProvider);
			}
			else {
				throw new KeyException("Unsupported algorithm: " + this.accessTokenJwsAlgorithm);
			}

			return new BearerAccessToken(accessToken.serialize(), this.accessTokenLifetime.getSeconds(), scope);
		}
		catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}

	public void setResourceScopes(Map<Scope.Value, String> resourceScopes) {
		this.resourceScopes = resourceScopes;
	}

	public void setAccessTokenLifetime(Duration accessTokenLifetime) {
		this.accessTokenLifetime = accessTokenLifetime;
	}

	public void setAccessTokenJwsAlgorithm(JWSAlgorithm accessTokenJwsAlgorithm) {
		this.accessTokenJwsAlgorithm = accessTokenJwsAlgorithm;
	}

	public void setAccessTokenScopeClaim(String accessTokenScopeClaim) {
		this.accessTokenScopeClaim = accessTokenScopeClaim;
	}

	public void setAccessTokenClientIdClaim(String accessTokenClientIdClaim) {
		this.accessTokenClientIdClaim = accessTokenClientIdClaim;
	}

	public void setAccessTokenSubjectClaims(List<String> accessTokenSubjectClaims) {
		this.accessTokenSubjectClaims = accessTokenSubjectClaims;
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
