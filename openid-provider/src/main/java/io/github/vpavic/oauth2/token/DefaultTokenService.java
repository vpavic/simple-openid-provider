package io.github.vpavic.oauth2.token;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.github.vpavic.oauth2.claim.UserClaimsLoader;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;

public class DefaultTokenService implements TokenService {

	private static final String SCOPE_CLAIM = "scope";

	private static final Scope DEFAULT_SCOPE = new Scope(OIDCScopeValue.OPENID);

	private static final BouncyCastleProvider jcaProvider = new BouncyCastleProvider();

	private final Issuer issuer;

	private final JwkSetLoader jwkSetLoader;

	private final UserClaimsLoader userClaimsLoader;

	private final RefreshTokenStore refreshTokenStore;

	private JWSAlgorithm accessTokenJwsAlgorithm = JWSAlgorithm.RS256;

	private Duration accessTokenLifetime = Duration.ofMinutes(10);

	private Duration refreshTokenLifetime = Duration.ZERO;

	private Duration idTokenLifetime = Duration.ofMinutes(15);

	private Map<Scope.Value, String> resourceScopes = new HashMap<>();

	private boolean frontChannelLogoutEnabled;

	public DefaultTokenService(Issuer issuer, JwkSetLoader jwkSetLoader, UserClaimsLoader userClaimsLoader,
			RefreshTokenStore refreshTokenStore) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(jwkSetLoader, "jwkSetLoader must not be null");
		Objects.requireNonNull(userClaimsLoader, "userClaimsLoader must not be null");
		Objects.requireNonNull(refreshTokenStore, "refreshTokenStore must not be null");

		this.issuer = issuer;
		this.jwkSetLoader = jwkSetLoader;
		this.userClaimsLoader = userClaimsLoader;
		this.refreshTokenStore = refreshTokenStore;
	}

	@Override
	public AccessToken createAccessToken(AccessTokenRequest accessTokenRequest) {
		Instant now = Instant.now();

		Subject subject = accessTokenRequest.getSubject();
		OIDCClientInformation client = accessTokenRequest.getClient();
		Scope scope = accessTokenRequest.getScope();

		Issuer issuer = new Issuer(this.issuer);
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
		UserInfo userInfo = this.userClaimsLoader.load(subject, DEFAULT_SCOPE);
		userInfo.setClaim(SCOPE_CLAIM, scope);

		try {
			JWTAssertionDetails details = new JWTAssertionDetails(issuer, userInfo.getSubject(), audience,
					expirationTime, null, issueTime, jwtId, userInfo.toJSONObject());
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
		Scope scope = refreshTokenRequest.getScope();

		RefreshToken refreshToken = new RefreshToken();
		Instant expiry = (!this.refreshTokenLifetime.isZero() && !this.refreshTokenLifetime.isNegative())
				? now.plus(this.refreshTokenLifetime)
				: null;
		RefreshTokenContext context = new RefreshTokenContext(refreshTokenRequest.getSubject(),
				refreshTokenRequest.getClientId(), scope, expiry);
		this.refreshTokenStore.save(refreshToken, context);

		return refreshToken;
	}

	@Override
	public JWT createIdToken(IdTokenRequest idTokenRequest) {
		Instant now = Instant.now();
		Subject subject = idTokenRequest.getSubject();
		OIDCClientInformation client = idTokenRequest.getClient();
		ClientID clientId = client.getID();
		JWSAlgorithm algorithm = client.getOIDCMetadata().getIDTokenJWSAlg();
		Issuer issuer = new Issuer(this.issuer);
		UserInfo userInfo = this.userClaimsLoader.load(subject,
				idTokenRequest.hasAccessToken() ? DEFAULT_SCOPE : idTokenRequest.getScope());
		List<Audience> audience = Audience.create(clientId.getValue());
		Date expirationTime = Date.from(now.plus(this.idTokenLifetime));
		Date issueTime = Date.from(now);

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(issuer, userInfo.getSubject(), audience, expirationTime,
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

	public void setAccessTokenJwsAlgorithm(JWSAlgorithm accessTokenJwsAlgorithm) {
		this.accessTokenJwsAlgorithm = accessTokenJwsAlgorithm;
	}

	public void setAccessTokenLifetime(Duration accessTokenLifetime) {
		this.accessTokenLifetime = accessTokenLifetime;
	}

	public void setRefreshTokenLifetime(Duration refreshTokenLifetime) {
		this.refreshTokenLifetime = refreshTokenLifetime;
	}

	public void setIdTokenLifetime(Duration idTokenLifetime) {
		this.idTokenLifetime = idTokenLifetime;
	}

	public void setFrontChannelLogoutEnabled(boolean frontChannelLogoutEnabled) {
		this.frontChannelLogoutEnabled = frontChannelLogoutEnabled;
	}

	public void setResourceScopes(Map<Scope.Value, String> resourceScopes) {
		this.resourceScopes = resourceScopes;
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
