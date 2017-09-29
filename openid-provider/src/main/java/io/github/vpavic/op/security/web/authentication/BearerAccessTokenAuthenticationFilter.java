package io.github.vpavic.op.security.web.authentication;

import java.io.IOException;
import java.time.Instant;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.vpavic.op.oauth2.jwk.JwkSetService;

public class BearerAccessTokenAuthenticationFilter extends OncePerRequestFilter {

	private static final String SCOPE_CLAIM = "scope";

	private static final Logger logger = LoggerFactory.getLogger(BearerAccessTokenAuthenticationFilter.class);

	private final String issuer;

	private final JwkSetService jwkSetService;

	private final AuthenticationManager authenticationManager;

	public BearerAccessTokenAuthenticationFilter(String issuer, JwkSetService jwkSetService,
			AuthenticationManager authenticationManager) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(jwkSetService, "jwkSetService must not be null");
		Objects.requireNonNull(authenticationManager, "authenticationManager must not be null");

		this.issuer = issuer;
		this.jwkSetService = jwkSetService;
		this.authenticationManager = authenticationManager;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
			UserInfoRequest userInfoRequest = UserInfoRequest.parse(httpRequest);

			ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,
					this.jwkSetService);
			jwtProcessor.setJWSKeySelector(keySelector);
			JWTClaimsSet claimsSet = jwtProcessor.process(userInfoRequest.getAccessToken().getValue(), null);

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
