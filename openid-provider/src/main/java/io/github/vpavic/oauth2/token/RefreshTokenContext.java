package io.github.vpavic.oauth2.token;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;

public class RefreshTokenContext implements Serializable {

	private final String principal;

	private final ClientID clientId;

	private final Scope scope;

	private final Instant expiry;

	public RefreshTokenContext(String principal, ClientID clientId, Scope scope, Instant expiry) {
		Objects.requireNonNull(principal, "principal must not be null");
		Objects.requireNonNull(clientId, "clientId must not be null");
		Objects.requireNonNull(scope, "scope must not be null");

		this.principal = principal;
		this.clientId = clientId;
		this.scope = scope;
		this.expiry = expiry;
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

	public Instant getExpiry() {
		return this.expiry;
	}

	public boolean isExpired() {
		return (this.expiry != null) && Instant.now().isAfter(this.expiry);
	}

}
