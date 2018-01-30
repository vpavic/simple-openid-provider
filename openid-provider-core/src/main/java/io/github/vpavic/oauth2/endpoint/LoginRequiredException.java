package io.github.vpavic.oauth2.endpoint;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

public class LoginRequiredException extends Exception {

	private final AuthenticationRequest authenticationRequest;

	LoginRequiredException(AuthenticationRequest authenticationRequest) {
		this.authenticationRequest = authenticationRequest;
	}

	public AuthenticationRequest getAuthenticationRequest() {
		return this.authenticationRequest;
	}

}
