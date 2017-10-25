package io.github.vpavic.oauth2.token;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

public final class RefreshTokenRequest {

	private final String principal;

	private final ClientID clientId;

	private final Scope scope;

	public RefreshTokenRequest(String principal, ClientID clientId, Scope scope) {
		Objects.requireNonNull(principal, "principal must not be null");
		Objects.requireNonNull(clientId, "clientId must not be null");
		Objects.requireNonNull(scope, "scope must not be null");

		this.principal = principal;
		this.clientId = clientId;
		this.scope = scope;
	}

	public String getPrincipal() {
		return this.principal;
	}

	public ClientID getClientId() {
		return this.clientId;
	}

	public Scope getScope() {
		return this.scope;
	}

}
