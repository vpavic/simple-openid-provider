package io.github.vpavic.op.oauth2.token;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

public class RefreshTokenContext implements Serializable {

	private final String principal;

	private final ClientID clientID;

	private final Scope scope;

	private final Instant expiry;

	public RefreshTokenContext(String principal, ClientID clientID, Scope scope, Instant expiry) {
		Objects.requireNonNull(principal, "principal must not be null");
		Objects.requireNonNull(clientID, "clientID must not be null");
		Objects.requireNonNull(scope, "scope must not be null");

		this.principal = principal;
		this.clientID = clientID;
		this.scope = scope;
		this.expiry = expiry;
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

	public Instant getExpiry() {
		return this.expiry;
	}

	public boolean isExpired() {
		return (this.expiry != null) && Instant.now().isAfter(this.expiry);
	}

}
