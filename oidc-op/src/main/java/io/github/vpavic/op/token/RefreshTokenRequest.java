package io.github.vpavic.op.token;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

public final class RefreshTokenRequest {

	private final String principal;

	private final ClientID clientID;

	private final Scope scope;

	public RefreshTokenRequest(String principal, ClientID clientID, Scope scope) {
		Objects.requireNonNull(principal, "principal must not be null");
		Objects.requireNonNull(clientID, "clientID must not be null");
		Objects.requireNonNull(scope, "scope must not be null");

		this.principal = principal;
		this.clientID = clientID;
		this.scope = scope;
	}

	public String getPrincipal() {
		return this.principal;
	}

	public ClientID getClientID() {
		return this.clientID;
	}

	public Scope getScope() {
		return this.scope;
	}

}
