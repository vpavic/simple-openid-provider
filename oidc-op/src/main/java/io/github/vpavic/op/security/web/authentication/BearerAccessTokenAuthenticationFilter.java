package io.github.vpavic.op.security.web.authentication;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.vpavic.op.key.KeyService;

public class BearerAccessTokenAuthenticationFilter extends OncePerRequestFilter {

	private static final String AUTHORIZATION_HEADER = "Authorization";

	private static final String SCOPE_CLAIM = "scope";

	private static final Logger logger = LoggerFactory.getLogger(BearerAccessTokenAuthenticationFilter.class);

	private final String issuer;

	private final KeyService keyService;

	private final AuthenticationManager authenticationManager;

	public BearerAccessTokenAuthenticationFilter(String issuer, KeyService keyService,
			AuthenticationManager authenticationManager) {
		this.issuer = Objects.requireNonNull(issuer);
		this.keyService = Objects.requireNonNull(keyService);
		this.authenticationManager = Objects.requireNonNull(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			BearerAccessToken accessToken = BearerAccessToken.parse(request.getHeader(AUTHORIZATION_HEADER));
			List<JWK> keys = this.keyService.findAll();

			ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			JWSKeySelector<SimpleSecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,
					new ImmutableJWKSet<>(new JWKSet(keys)));
			jwtProcessor.setJWSKeySelector(keySelector);
			JWTClaimsSet claimsSet = jwtProcessor.process(accessToken.getValue(), null);

			if (!this.issuer.equals(claimsSet.getIssuer())) {
				throw new Exception("Invalid issuer");
			}

			if (!claimsSet.getAudience().contains(this.issuer)) {
				throw new Exception("Invalid audience");
			}

			if (Instant.now().isAfter(claimsSet.getExpirationTime().toInstant())) {
				throw new Exception("Access token has expired");
			}

			if (!StringUtils.hasText(claimsSet.getStringClaim(SCOPE_CLAIM))) {
				throw new Exception("Invalid scope");
			}

			String username = claimsSet.getSubject();
			PreAuthenticatedAuthenticationToken authToken = new PreAuthenticatedAuthenticationToken(username, "");
			authToken.setDetails(claimsSet);
			Authentication authResult = this.authenticationManager.authenticate(authToken);
			SecurityContextHolder.getContext().setAuthentication(authResult);
		}
		catch (Exception e) {
			logger.debug("Bearer authentication attempt failed: {}", e.getMessage());
		}

		filterChain.doFilter(request, response);
	}

}
