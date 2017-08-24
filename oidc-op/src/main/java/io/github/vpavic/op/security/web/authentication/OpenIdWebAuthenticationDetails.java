package io.github.vpavic.op.security.web.authentication;

import java.time.Instant;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

public class OpenIdWebAuthenticationDetails extends WebAuthenticationDetails {

	private final Instant authenticationTime;

	public OpenIdWebAuthenticationDetails(HttpServletRequest request) {
		super(request);
		this.authenticationTime = Instant.now();
	}

	public Instant getAuthenticationTime() {
		return this.authenticationTime;
	}

}
