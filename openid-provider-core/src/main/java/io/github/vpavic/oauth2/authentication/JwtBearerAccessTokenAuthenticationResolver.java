package io.github.vpavic.oauth2.authentication;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import io.github.vpavic.oauth2.jwk.JwkSetLoader;

/**
 * A JWT Access token based {@link BearerTokenAuthenticationResolver} implementation.
 *
 * @author Vedran Pavic
 */
public class JwtBearerAccessTokenAuthenticationResolver implements BearerTokenAuthenticationResolver {

	private final Issuer issuer;

	private final JwkSetLoader jwkSetLoader;

	private JWSAlgorithm accessTokenJwsAlgorithm = JWSAlgorithm.RS256;

	public JwtBearerAccessTokenAuthenticationResolver(Issuer issuer, JwkSetLoader jwkSetLoader) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(jwkSetLoader, "jwkSetLoader must not be null");
		this.issuer = issuer;
		this.jwkSetLoader = jwkSetLoader;
	}

	@Override
	public Authentication resolveAuthentication(String bearerToken) throws Exception {
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
		JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(this.accessTokenJwsAlgorithm,
				(jwkSelector, context) -> jwkSelector.select(this.jwkSetLoader.load()));
		jwtProcessor.setJWSKeySelector(keySelector);
		JWTClaimsSet claimsSet = jwtProcessor.process(bearerToken, null);

		if (!this.issuer.getValue().equals(claimsSet.getIssuer())) {
			throw new Exception("Invalid issuer");
		}
		if (!claimsSet.getAudience().contains(this.issuer.getValue())) {
			throw new Exception("Invalid audience");
		}
		if (Instant.now().isAfter(claimsSet.getExpirationTime().toInstant())) {
			throw new Exception("Access token has expired");
		}
		List<String> scopes = claimsSet.getStringListClaim("scp");
		if (scopes.isEmpty() || !scopes.contains(OIDCScopeValue.OPENID.getValue())) {
			throw new Exception("Invalid scope");
		}

		String username = claimsSet.getSubject();
		PreAuthenticatedAuthenticationToken authentication = new PreAuthenticatedAuthenticationToken(username, "",
				Collections.emptyList());
		authentication.setDetails(claimsSet);
		return authentication;
	}

	public void setAccessTokenJwsAlgorithm(JWSAlgorithm accessTokenJwsAlgorithm) {
		this.accessTokenJwsAlgorithm = accessTokenJwsAlgorithm;
	}

}
