package io.github.vpavic.op.config;

import java.io.IOException;
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
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.vpavic.op.key.KeyService;

public class BearerAccessTokenAuthenticationFilter extends OncePerRequestFilter {

	private static final Logger logger = LoggerFactory.getLogger(BearerAccessTokenAuthenticationFilter.class);

	private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private final KeyService keyService;

	private final AuthenticationManager authenticationManager;

	public BearerAccessTokenAuthenticationFilter(KeyService keyService, AuthenticationManager authenticationManager) {
		this.keyService = Objects.requireNonNull(keyService);
		this.authenticationManager = Objects.requireNonNull(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);

		try {
			BearerAccessToken accessToken = BearerAccessToken.parse(httpRequest);
			List<JWK> keys = this.keyService.findAll();

			ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			JWSKeySelector<SimpleSecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,
					new ImmutableJWKSet<>(new JWKSet(keys)));
			jwtProcessor.setJWSKeySelector(keySelector);
			JWTClaimsSet claimsSet = jwtProcessor.process(accessToken.getValue(), null);

			String username = claimsSet.getSubject();
			PreAuthenticatedAuthenticationToken authToken = new PreAuthenticatedAuthenticationToken(username, "");
			authToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
			Authentication authResult = this.authenticationManager.authenticate(authToken);
			SecurityContextHolder.getContext().setAuthentication(authResult);
		}
		catch (Exception e) {
			logger.warn("Bearer authentication attempt failed: {}", e.getMessage());
		}

		filterChain.doFilter(request, response);
	}

}
