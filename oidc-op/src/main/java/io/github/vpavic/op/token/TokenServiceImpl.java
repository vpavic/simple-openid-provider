package io.github.vpavic.op.token;

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
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
import org.springframework.stereotype.Service;

import io.github.vpavic.op.config.OpenIdProviderProperties;
import io.github.vpavic.op.key.KeyService;
import io.github.vpavic.op.userinfo.UserInfoMapper;

@Service
public class TokenServiceImpl implements TokenService {

	private static final String SCOPE_CLAIM = "scope";

	private static final JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;

	private final OpenIdProviderProperties properties;

	private final KeyService keyService;

	private final RefreshTokenStore refreshTokenStore;

	public TokenServiceImpl(OpenIdProviderProperties properties, KeyService keyService,
			RefreshTokenStore refreshTokenStore) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(keyService, "keyService must not be null");
		Objects.requireNonNull(refreshTokenStore, "refreshTokenStore must not be null");

		this.properties = properties;
		this.keyService = keyService;
		this.refreshTokenStore = refreshTokenStore;
	}

	@Override
	public AccessToken createAccessToken(AccessTokenRequest accessTokenRequest) {
		Instant issuedAt = Instant.now();
		int tokenLifetime = this.properties.getAccessToken().getLifetime();

		JWK jwk = this.keyService.findActive();

		// @formatter:off
		JWSHeader header = new JWSHeader.Builder(jwsAlgorithm)
				.keyID(jwk.getKeyID())
				.build();
		// @formatter:on

		String principal = accessTokenRequest.getPrincipal();
		Scope scope = accessTokenRequest.getScope();

		// @formatter:off
		JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
				.issuer(this.properties.getIssuer())
				.subject(principal)
				.audience(this.properties.getIssuer())
				.expirationTime(Date.from(issuedAt.plusSeconds(tokenLifetime)))
				.issueTime(Date.from(issuedAt))
				.jwtID(UUID.randomUUID().toString())
				.claim(SCOPE_CLAIM, scope.toString());
		// @formatter:on

		ClaimsMapper claimsMapper = accessTokenRequest.getClaimsMapper();

		if (claimsMapper != null) {
			Map<String, Object> claims = claimsMapper.map(principal);
			claims.forEach(claimsSetBuilder::claim);
		}

		JWTClaimsSet claimsSet = claimsSetBuilder.build();

		try {
			SignedJWT accessToken = new SignedJWT(header, claimsSet);
			RSASSASigner signer = new RSASSASigner((RSAKey) jwk);
			accessToken.sign(signer);

			return new BearerAccessToken(accessToken.serialize(), tokenLifetime, scope);
		}
		catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public RefreshToken createRefreshToken(RefreshTokenRequest refreshTokenRequest) {
		Scope scope = refreshTokenRequest.getScope();

		if (!scope.contains(OIDCScopeValue.OFFLINE_ACCESS)) {
			throw new IllegalArgumentException("Scope '" + OIDCScopeValue.OFFLINE_ACCESS + "' is required");
		}

		Instant issuedAt = Instant.now();
		int tokenLifetime = this.properties.getRefreshToken().getLifetime();

		RefreshToken refreshToken = new RefreshToken();
		Instant expiry = (tokenLifetime > 0) ? issuedAt.plusSeconds(tokenLifetime) : null;
		RefreshTokenContext context = new RefreshTokenContext(refreshTokenRequest.getPrincipal(),
				refreshTokenRequest.getClientID(), scope, expiry);
		this.refreshTokenStore.save(refreshToken, context);

		return refreshToken;
	}

	@Override
	public JWT createIdToken(IdTokenRequest idTokenRequest) {
		Scope scope = idTokenRequest.getScope();

		if (!scope.contains(OIDCScopeValue.OPENID)) {
			throw new IllegalArgumentException("Scope '" + OIDCScopeValue.OPENID + "' is required");
		}

		Instant issuedAt = Instant.now();

		JWK jwk = this.keyService.findActive();

		// @formatter:off
		JWSHeader header = new JWSHeader.Builder(jwsAlgorithm)
				.keyID(jwk.getKeyID())
				.build();
		// @formatter:on

		String principal = idTokenRequest.getPrincipal();
		ClientID clientID = idTokenRequest.getClientID();

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(new Issuer(this.properties.getIssuer()),
				new Subject(principal), Audience.create(clientID.getValue()),
				Date.from(issuedAt.plusSeconds(this.properties.getIdToken().getLifetime())), Date.from(issuedAt));

		claimsSet.setAuthenticationTime(Date.from(idTokenRequest.getAuthenticationTime()));
		claimsSet.setNonce(idTokenRequest.getNonce());
		claimsSet.setACR(idTokenRequest.getAcr());
		claimsSet.setAMR(Collections.singletonList(idTokenRequest.getAmr()));
		claimsSet.setAuthorizedParty(new AuthorizedParty(clientID.getValue()));

		if (this.properties.getFrontChannelLogout().isEnabled()) {
			claimsSet.setSessionID(new SessionID(idTokenRequest.getSessionId()));
		}

		AccessToken accessToken = idTokenRequest.getAccessToken();

		if (accessToken != null) {
			claimsSet.setAccessTokenHash(AccessTokenHash.compute(accessToken, jwsAlgorithm));
		}

		AuthorizationCode code = idTokenRequest.getCode();

		if (code != null) {
			claimsSet.setCodeHash(CodeHash.compute(code, jwsAlgorithm));
		}

		UserInfoMapper userInfoMapper = idTokenRequest.getUserInfoMapper();

		if (userInfoMapper != null) {
			UserInfo userInfo = userInfoMapper.map(principal, scope);
			userInfo.toJSONObject().forEach(claimsSet::setClaim);
		}

		try {
			SignedJWT idToken = new SignedJWT(header, claimsSet.toJWTClaimsSet());
			RSASSASigner signer = new RSASSASigner((RSAKey) jwk);
			idToken.sign(signer);

			return idToken;
		}
		catch (ParseException | JOSEException e) {
			throw new RuntimeException(e);
		}
	}

}
