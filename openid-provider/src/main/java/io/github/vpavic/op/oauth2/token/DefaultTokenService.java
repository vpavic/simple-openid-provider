package io.github.vpavic.op.oauth2.token;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeyException;
import com.nimbusds.jose.KeySourceException;
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

import io.github.vpavic.op.config.OpenIdProviderProperties;
import io.github.vpavic.op.oauth2.jwk.JwkSetLoader;
import io.github.vpavic.op.oauth2.userinfo.UserInfoMapper;

class DefaultTokenService implements TokenService {

	private static final String SCOPE_CLAIM = "scope";

	private static final JWSAlgorithm defaultAlgorithm = JWSAlgorithm.RS256;

	private static final BouncyCastleProvider jcaProvider = new BouncyCastleProvider();

	private final OpenIdProviderProperties properties;

	private final JwkSetLoader jwkSetLoader;

	private final RefreshTokenStore refreshTokenStore;

	DefaultTokenService(OpenIdProviderProperties properties, JwkSetLoader jwkSetLoader,
			RefreshTokenStore refreshTokenStore) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(jwkSetLoader, "jwkSetLoader must not be null");
		Objects.requireNonNull(refreshTokenStore, "refreshTokenStore must not be null");

		this.properties = properties;
		this.jwkSetLoader = jwkSetLoader;
		this.refreshTokenStore = refreshTokenStore;
	}

	@Override
	public AccessToken createAccessToken(AccessTokenRequest accessTokenRequest) {
		Instant now = Instant.now();
		int tokenLifetime = this.properties.getAccessToken().getLifetime();

		String principal = accessTokenRequest.getPrincipal();
		Scope scope = accessTokenRequest.getScope();
		AccessTokenClaimsMapper accessTokenClaimsMapper = accessTokenRequest.getAccessTokenClaimsMapper();

		Issuer issuer = new Issuer(this.properties.getIssuer());
		Subject subject = new Subject(principal);
		List<Audience> audience = new ArrayList<>();
		audience.add(new Audience(this.properties.getIssuer()));

		for (Scope.Value value : scope) {
			String resource = this.properties.getAuthorization().getResourceScopes().get(value);

			if (resource != null) {
				audience.add(new Audience(resource));
			}
		}

		Date expirationTime = Date.from(now.plusSeconds(tokenLifetime));
		Date issueTime = Date.from(now);
		JWTID jwtId = new JWTID();
		Map<String, Object> claims = new HashMap<>();
		claims.put(SCOPE_CLAIM, scope);

		if (accessTokenClaimsMapper != null) {
			claims.putAll(accessTokenClaimsMapper.map(principal));
		}

		try {
			JWTAssertionDetails details = new JWTAssertionDetails(issuer, subject, audience, expirationTime, null,
					issueTime, jwtId, claims);
			RSAKey rsaKey = (RSAKey) resolveJwk(defaultAlgorithm);
			SignedJWT accessToken = JWTAssertionFactory.create(details, defaultAlgorithm, rsaKey.toRSAPrivateKey(),
					rsaKey.getKeyID(), null);

			return new BearerAccessToken(accessToken.serialize(), tokenLifetime, scope);
		}
		catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public RefreshToken createRefreshToken(RefreshTokenRequest refreshTokenRequest) {
		Instant now = Instant.now();
		Scope scope = refreshTokenRequest.getScope();

		if (!scope.contains(OIDCScopeValue.OFFLINE_ACCESS)) {
			throw new IllegalArgumentException("Scope '" + OIDCScopeValue.OFFLINE_ACCESS + "' is required");
		}

		int tokenLifetime = this.properties.getRefreshToken().getLifetime();

		RefreshToken refreshToken = new RefreshToken();
		Instant expiry = (tokenLifetime > 0) ? now.plusSeconds(tokenLifetime) : null;
		RefreshTokenContext context = new RefreshTokenContext(refreshTokenRequest.getPrincipal(),
				refreshTokenRequest.getClientID(), scope, expiry);
		this.refreshTokenStore.save(refreshToken, context);

		return refreshToken;
	}

	@Override
	public JWT createIdToken(IdTokenRequest idTokenRequest) {
		Instant now = Instant.now();
		Scope scope = idTokenRequest.getScope();

		if (!scope.contains(OIDCScopeValue.OPENID)) {
			throw new IllegalArgumentException("Scope '" + OIDCScopeValue.OPENID + "' is required");
		}

		String principal = idTokenRequest.getPrincipal();
		OIDCClientInformation client = idTokenRequest.getClient();
		ClientID clientID = client.getID();
		JWSAlgorithm algorithm = client.getOIDCMetadata().getIDTokenJWSAlg();
		Issuer issuer = new Issuer(this.properties.getIssuer());
		Subject subject = new Subject(principal);
		List<Audience> audience = Audience.create(clientID.getValue());
		Date expirationTime = Date.from(now.plusSeconds(this.properties.getIdToken().getLifetime()));
		Date issueTime = Date.from(now);

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(issuer, subject, audience, expirationTime, issueTime);
		claimsSet.setAuthenticationTime(Date.from(idTokenRequest.getAuthenticationTime()));
		claimsSet.setNonce(idTokenRequest.getNonce());
		claimsSet.setACR(idTokenRequest.getAcr());
		claimsSet.setAMR(Collections.singletonList(idTokenRequest.getAmr()));
		claimsSet.setAuthorizedParty(new AuthorizedParty(clientID.getValue()));

		if (this.properties.getFrontChannelLogout().isEnabled()) {
			SessionID sessionId = new SessionID(idTokenRequest.getSessionId());
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

		IdTokenClaimsMapper idTokenClaimsMapper = idTokenRequest.getIdTokenClaimsMapper();

		if (idTokenClaimsMapper != null) {
			Map<String, Object> claims = idTokenClaimsMapper.map(principal);
			claims.forEach(claimsSet::setClaim);
		}

		UserInfoMapper userInfoMapper = idTokenRequest.getUserInfoMapper();

		if (userInfoMapper != null) {
			UserInfo userInfo = userInfoMapper.map(principal, scope);
			userInfo.toJSONObject().forEach(claimsSet::setClaim);
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

	private JWK resolveJwk(JWSAlgorithm algorithm) throws KeySourceException {
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
