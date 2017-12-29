package io.github.vpavic.oauth2.token;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
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
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionFactory;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.AuthorizedParty;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.apache.commons.collections4.SetUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.github.vpavic.oauth2.claim.ClaimHelper;
import io.github.vpavic.oauth2.claim.ClaimSource;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenContext;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenStore;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;

public class DefaultTokenService implements TokenService {

	private static final Scope SCOPE_OPENID = new Scope(OIDCScopeValue.OPENID);

	private static final BouncyCastleProvider jcaProvider = new BouncyCastleProvider();

	private final Issuer issuer;

	private final JwkSetLoader jwkSetLoader;

	private final ClaimSource claimSource;

	private final RefreshTokenStore refreshTokenStore;

	private Map<Scope.Value, String> resourceScopes = new HashMap<>();

	private Duration accessTokenLifetime = Duration.ofMinutes(10);

	private JWSAlgorithm accessTokenJwsAlgorithm = JWSAlgorithm.RS256;

	private String accessTokenScopeClaim = "scp";

	private String accessTokenClientIdClaim = "cid";

	private List<String> accessTokenSubjectClaims = new ArrayList<>();

	private Duration refreshTokenLifetime = Duration.ZERO;

	private Duration idTokenLifetime = Duration.ofMinutes(15);

	private Map<Scope.Value, List<String>> scopeClaims = new HashMap<>();

	private boolean frontChannelLogoutEnabled;

	public DefaultTokenService(Issuer issuer, JwkSetLoader jwkSetLoader, ClaimSource claimSource,
			RefreshTokenStore refreshTokenStore) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(jwkSetLoader, "jwkSetLoader must not be null");
		Objects.requireNonNull(claimSource, "claimSource must not be null");
		Objects.requireNonNull(refreshTokenStore, "refreshTokenStore must not be null");
		this.issuer = issuer;
		this.jwkSetLoader = jwkSetLoader;
		this.claimSource = claimSource;
		this.refreshTokenStore = refreshTokenStore;
	}

	@Override
	public AccessToken createAccessToken(AccessTokenRequest accessTokenRequest) {
		Instant now = Instant.now();

		Subject subject = accessTokenRequest.getSubject();
		OIDCClientInformation client = accessTokenRequest.getClient();
		Scope scope = accessTokenRequest.getScope();

		List<Audience> audience = new ArrayList<>();
		audience.add(new Audience(this.issuer));

		for (Scope.Value value : scope) {
			String resource = this.resourceScopes.get(value);

			if (resource != null) {
				audience.add(new Audience(resource));
			}
		}

		Date expirationTime = Date.from(now.plus(this.accessTokenLifetime));
		Date issueTime = Date.from(now);
		JWTID jwtId = new JWTID(UUID.randomUUID().toString());
		UserInfo userInfo = this.claimSource.load(subject, new HashSet<>(this.accessTokenSubjectClaims));
		userInfo.setClaim(this.accessTokenScopeClaim, scope);
		userInfo.setClaim(this.accessTokenClientIdClaim, client.getID());

		try {
			JWTAssertionDetails details = new JWTAssertionDetails(this.issuer, userInfo.getSubject(), audience,
					expirationTime, issueTime, issueTime, jwtId, userInfo.toJSONObject());
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

	@Override
	public RefreshToken createRefreshToken(RefreshTokenRequest refreshTokenRequest) {
		Instant now = Instant.now();
		ClientID clientId = refreshTokenRequest.getClientId();
		Subject subject = refreshTokenRequest.getSubject();
		Scope scope = refreshTokenRequest.getScope();

		RefreshTokenContext context = this.refreshTokenStore.findByClientIdAndSubject(clientId, subject);

		if (context == null || !SetUtils.isEqualSet(context.getScope(), scope)) {
			if (context != null) {
				this.refreshTokenStore.revoke(context.getRefreshToken());
			}
			Instant expiry = (!this.refreshTokenLifetime.isZero() && !this.refreshTokenLifetime.isNegative())
					? now.plus(this.refreshTokenLifetime)
					: null;
			context = new RefreshTokenContext(new RefreshToken(), clientId, subject, scope, expiry);
			this.refreshTokenStore.save(context);
		}

		return context.getRefreshToken();
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
		claimsSet.setAMR(Collections.singletonList(idTokenRequest.getAmr()));
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

	public void setRefreshTokenLifetime(Duration refreshTokenLifetime) {
		this.refreshTokenLifetime = refreshTokenLifetime;
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
