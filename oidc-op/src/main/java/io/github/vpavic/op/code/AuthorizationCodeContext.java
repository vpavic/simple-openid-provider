package io.github.vpavic.op.code;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.token.Tokens;

public class AuthorizationCodeContext {

	private final AuthorizationRequest authRequest;

	private final Tokens tokens;

	public AuthorizationCodeContext(AuthorizationRequest authRequest, Tokens tokens) {
		this.authRequest = Objects.requireNonNull(authRequest);
		this.tokens = Objects.requireNonNull(tokens);
	}

	public AuthorizationRequest getAuthRequest() {
		return this.authRequest;
	}

	public Tokens getTokens() {
		return this.tokens;
	}

}
