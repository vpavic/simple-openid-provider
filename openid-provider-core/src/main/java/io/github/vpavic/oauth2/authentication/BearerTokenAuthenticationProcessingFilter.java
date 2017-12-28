package io.github.vpavic.oauth2.authentication;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A pre-authenticated filter that extracts {@link Authentication} from Bearer token located in {@code Authorization}
 * HTTP header.
 *
 * @author Vedran Pavic
 */
public class BearerTokenAuthenticationProcessingFilter extends OncePerRequestFilter {

	private static final Logger logger = LoggerFactory.getLogger(BearerTokenAuthenticationProcessingFilter.class);

	private final BearerTokenAuthenticationResolver authenticationResolver;

	public BearerTokenAuthenticationProcessingFilter(BearerTokenAuthenticationResolver authenticationResolver) {
		Objects.requireNonNull(authenticationResolver, "authenticationResolver must not be null");
		this.authenticationResolver = authenticationResolver;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			String authorization = request.getHeader("Authorization");
			BearerAccessToken accessToken = BearerAccessToken.parse(authorization);
			Authentication authentication = this.authenticationResolver.resolveAuthentication(accessToken.getValue());
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}
		catch (Exception e) {
			logger.debug("Bearer token authentication attempt failed: {}", e.getMessage());
		}

		filterChain.doFilter(request, response);
	}

}
