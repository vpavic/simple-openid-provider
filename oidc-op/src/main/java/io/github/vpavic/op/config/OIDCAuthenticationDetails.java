package io.github.vpavic.op.config;

import java.time.Instant;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

public class OIDCAuthenticationDetails extends WebAuthenticationDetails {

	private final Instant authenticationTime;

	public OIDCAuthenticationDetails(HttpServletRequest request, Instant authenticationTime) {
		super(request);
		this.authenticationTime = authenticationTime;
	}

	public Instant getAuthenticationTime() {
		return this.authenticationTime;
	}

}
