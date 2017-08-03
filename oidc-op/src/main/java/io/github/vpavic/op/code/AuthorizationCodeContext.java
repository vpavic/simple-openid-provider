package io.github.vpavic.op.code;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import org.springframework.security.core.Authentication;

public class AuthorizationCodeContext {

	private final AuthorizationRequest authRequest;

	private final Authentication authentication;

	public AuthorizationCodeContext(AuthorizationRequest authRequest, Authentication authentication) {
		this.authRequest = Objects.requireNonNull(authRequest);
		this.authentication = Objects.requireNonNull(authentication);
	}

	public AuthorizationRequest getAuthRequest() {
		return this.authRequest;
	}

	public Authentication getAuthentication() {
		return this.authentication;
	}

}
