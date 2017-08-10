package io.github.vpavic.op.token;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.github.vpavic.op.config.OpenIdProviderProperties;
import io.github.vpavic.op.key.KeyService;

@Service
public class TokenServiceImpl implements TokenService {

	private final OpenIdProviderProperties properties;

	private final KeyService keyService;

	public TokenServiceImpl(OpenIdProviderProperties properties, KeyService keyService) {
		this.properties = properties;
		this.keyService = Objects.requireNonNull(keyService);
	}

	@Override
	public AccessToken createAccessToken(UserDetails principal, ClientID clientID, Scope scope) {
		Instant issuedAt = Instant.now();
		Duration accessTokenValidityDuration = this.properties.getAccessTokenValidityDuration();

		JWK defaultJwk = this.keyService.findActive();
		JWSHeader header = createJwsHeader(defaultJwk);
		JWSSigner signer = createJwsSigner(defaultJwk);

		// @formatter:off
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(this.properties.getIssuer())
				.subject(principal.getName())
				.audience(clientID.getValue())
				.expirationTime(Date.from(issuedAt.plus(accessTokenValidityDuration)))
				.issueTime(Date.from(issuedAt))
				.build();
		// @formatter:on

		try {
			SignedJWT accessToken = new SignedJWT(header, claimsSet);
			accessToken.sign(signer);
			return new BearerAccessToken(accessToken.serialize(), accessTokenValidityDuration.getSeconds(), scope);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public RefreshToken createRefreshToken() {
		return new RefreshToken();
	}

	@Override
	public JWT createIdToken(UserDetails principal, ClientID clientID, Scope scope, Nonce nonce) {
		Instant issuedAt = Instant.now();

		JWK defaultJwk = this.keyService.findActive();
		JWSHeader header = createJwsHeader(defaultJwk);
		JWSSigner signer = createJwsSigner(defaultJwk);

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(new Issuer(this.properties.getIssuer()),
				new Subject(principal.getName()), Audience.create(clientID.getValue()),
				Date.from(issuedAt.plus(this.properties.getIdTokenValidityDuration())), Date.from(issuedAt));

		claimsSet.setNonce(nonce);
		claimsSet.setAMR(Collections.singletonList(AMR.PWD));
		claimsSet.setAuthorizedParty(new AuthorizedParty(clientID.getValue()));

		try {
			SignedJWT idToken = new SignedJWT(header, claimsSet.toJWTClaimsSet());
			idToken.sign(signer);
			return idToken;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private JWSHeader createJwsHeader(JWK jwk) {
		// @formatter:off
		return new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(JOSEObjectType.JWT)
				.keyID(jwk.getKeyID())
				.build();
		// @formatter:on
	}

	private JWSSigner createJwsSigner(JWK jwk) {
		try {
			return new RSASSASigner((RSAKey) jwk);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
