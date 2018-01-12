package io.github.vpavic.oauth2.authentication;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

import io.github.vpavic.oauth2.jwk.JwkSetLoader;

/**
 * A JWT based {@link AccessTokenClaimsResolver} implementation.
 *
 * @author Vedran Pavic
 */
public class JwtAccessTokenClaimsResolver implements AccessTokenClaimsResolver {

	private final Issuer issuer;

	private final JwkSetLoader jwkSetLoader;

	private JWSAlgorithm accessTokenJwsAlgorithm = JWSAlgorithm.RS256;

	private String accessTokenScopeClaim = "scp";

	public JwtAccessTokenClaimsResolver(Issuer issuer, JwkSetLoader jwkSetLoader) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(jwkSetLoader, "jwkSetLoader must not be null");
		this.issuer = issuer;
		this.jwkSetLoader = jwkSetLoader;
	}

	@Override
	public Map<String, Object> resolveClaims(AccessToken accessToken) throws Exception {
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
		JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(this.accessTokenJwsAlgorithm,
				(jwkSelector, context) -> jwkSelector.select(this.jwkSetLoader.load()));
		jwtProcessor.setJWSKeySelector(keySelector);
		JWTClaimsSet claimsSet = jwtProcessor.process(accessToken.getValue(), null);

		if (!this.issuer.getValue().equals(claimsSet.getIssuer())) {
			throw new Exception("Invalid issuer");
		}
		if (!claimsSet.getAudience().contains(this.issuer.getValue())) {
			throw new Exception("Invalid audience");
		}
		if (Instant.now().isAfter(claimsSet.getExpirationTime().toInstant())) {
			throw new Exception("Access token has expired");
		}
		List<String> scopes = claimsSet.getStringListClaim(this.accessTokenScopeClaim);
		if (scopes.isEmpty() || !scopes.contains(OIDCScopeValue.OPENID.getValue())) {
			throw new Exception("Invalid scope");
		}

		return claimsSet.getClaims();
	}

	public void setAccessTokenJwsAlgorithm(JWSAlgorithm accessTokenJwsAlgorithm) {
		this.accessTokenJwsAlgorithm = accessTokenJwsAlgorithm;
	}

	public void setAccessTokenScopeClaim(String accessTokenScopeClaim) {
		this.accessTokenScopeClaim = accessTokenScopeClaim;
	}

}