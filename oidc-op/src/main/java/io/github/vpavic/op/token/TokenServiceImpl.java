package io.github.vpavic.op.token;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.AMR;
import com.nimbusds.openid.connect.sdk.claims.AuthorizedParty;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import org.springframework.stereotype.Service;

import io.github.vpavic.op.config.OpenIdProviderProperties;
import io.github.vpavic.op.key.KeyService;

@Service
public class TokenServiceImpl implements TokenService {

	private final OpenIdProviderProperties properties;

	private final KeyService keyService;

	private final RefreshTokenStore refreshTokenStore;

	public TokenServiceImpl(OpenIdProviderProperties properties, KeyService keyService,
			RefreshTokenStore refreshTokenStore) {
		this.properties = properties;
		this.keyService = Objects.requireNonNull(keyService);
		this.refreshTokenStore = Objects.requireNonNull(refreshTokenStore);
	}

	@Override
	public AccessToken createAccessToken(String principal, ClientID clientID, Scope scope) {
		Instant issuedAt = Instant.now();
		Duration accessTokenValidityDuration = this.properties.getAccessTokenValidityDuration();

		JWK jwk = this.keyService.findActive();

		// @formatter:off
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(JOSEObjectType.JWT)
				.keyID(jwk.getKeyID())
				.build();
		// @formatter:on

		// @formatter:off
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(this.properties.getIssuer())
				.subject(principal)
				.audience(this.properties.getIssuer())
				.expirationTime(Date.from(issuedAt.plus(accessTokenValidityDuration)))
				.issueTime(Date.from(issuedAt))
				.jwtID(UUID.randomUUID().toString())
				.build();
		// @formatter:on

		try {
			SignedJWT accessToken = new SignedJWT(header, claimsSet);
			RSASSASigner signer = new RSASSASigner((RSAKey) jwk);
			accessToken.sign(signer);
			return new BearerAccessToken(accessToken.serialize(), accessTokenValidityDuration.getSeconds(), scope);
		}
		catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public RefreshToken createRefreshToken(String principal, ClientID clientID, Scope scope) {
		Instant issuedAt = Instant.now();
		Duration refreshTokenValidityDuration = this.properties.getRefreshTokenValidityDuration();

		RefreshToken refreshToken = new RefreshToken();
		Instant expiry = issuedAt.plus(refreshTokenValidityDuration);
		RefreshTokenContext context = new RefreshTokenContext(principal, clientID, scope, expiry);
		this.refreshTokenStore.save(refreshToken, context);
		return refreshToken;
	}

	@Override
	public JWT createIdToken(String principal, ClientID clientID, Scope scope, Instant authenticationTime,
			String sessionId, Nonce nonce) {
		Instant issuedAt = Instant.now();

		JWK jwk = this.keyService.findActive();

		// @formatter:off
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(JOSEObjectType.JWT)
				.keyID(jwk.getKeyID())
				.build();
		// @formatter:on

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(new Issuer(this.properties.getIssuer()),
				new Subject(principal), Audience.create(clientID.getValue()),
				Date.from(issuedAt.plus(this.properties.getIdTokenValidityDuration())), Date.from(issuedAt));

		claimsSet.setSessionID(new SessionID(sessionId));
		claimsSet.setAuthenticationTime(Date.from(authenticationTime));
		claimsSet.setNonce(nonce);
		claimsSet.setAMR(Collections.singletonList(AMR.PWD));
		claimsSet.setAuthorizedParty(new AuthorizedParty(clientID.getValue()));

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
