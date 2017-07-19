package io.github.vpavic.op.token;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Objects;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.springframework.stereotype.Service;

import io.github.vpavic.op.key.KeyService;

@Service
public class TokenServiceImpl implements TokenService {

	private static final Issuer issuer = new Issuer("http://localhost:6432");

	private final KeyService keyService;

	public TokenServiceImpl(KeyService keyService) {
		this.keyService = Objects.requireNonNull(keyService);
	}

	@Override
	public Tokens createTokens(AuthorizationRequest request, Principal principal) {
		BearerAccessToken accessToken = createAccessToken();
		RefreshToken refreshToken = createRefreshToken();
		return new Tokens(accessToken, refreshToken);
	}

	@Override
	public OIDCTokens createTokens(AuthenticationRequest request, Principal principal) {
		String idToken = createIdToken(request, principal);
		BearerAccessToken accessToken = createAccessToken();
		RefreshToken refreshToken = createRefreshToken();
		return new OIDCTokens(idToken, accessToken, refreshToken);
	}

	private BearerAccessToken createAccessToken() {
		return new BearerAccessToken();
	}

	private RefreshToken createRefreshToken() {
		return new RefreshToken();
	}

	private String createIdToken(AuthenticationRequest authRequest, Principal principal) {
		Instant now = Instant.now();

		JWK defaultJwk = this.keyService.findDefault();

		// @formatter:off
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(JOSEObjectType.JWT)
				.keyID(defaultJwk.getKeyID())
				.build();
		// @formatter:on

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(issuer, new Subject(principal.getName()),
				Audience.create(authRequest.getClientID().getValue()), Date.from(now.plus(30, ChronoUnit.MINUTES)),
				Date.from(now));

		if (authRequest.getNonce() != null) {
			claimsSet.setNonce(authRequest.getNonce());
		}

		try {
			SignedJWT idToken = new SignedJWT(header, claimsSet.toJWTClaimsSet());
			JWSSigner signer = new RSASSASigner((RSAKey) defaultJwk);
			idToken.sign(signer);
			return idToken.serialize();
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
