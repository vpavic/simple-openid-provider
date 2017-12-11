package io.github.vpavic.oauth2.authentication;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
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
			HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
			UserInfoRequest userInfoRequest = UserInfoRequest.parse(httpRequest);
			Authentication authentication = this.authenticationResolver
					.resolveAuthentication(userInfoRequest.getAccessToken().getValue());
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}
		catch (Exception e) {
			logger.debug("Bearer token authentication attempt failed: {}", e.getMessage());
		}

		filterChain.doFilter(request, response);
	}

}
