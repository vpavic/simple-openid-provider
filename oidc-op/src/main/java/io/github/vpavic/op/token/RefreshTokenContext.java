package io.github.vpavic.op.token;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.springframework.security.core.AuthenticatedPrincipal;

public class RefreshTokenContext implements Serializable {

	private final AuthenticatedPrincipal principal;

	private final ClientID clientID;

	private final Scope scope;

	private final Instant expiry;

	public RefreshTokenContext(AuthenticatedPrincipal principal, ClientID clientID, Scope scope, Instant expiry) {
		this.principal = Objects.requireNonNull(principal);
		this.clientID = Objects.requireNonNull(clientID);
		this.scope = Objects.requireNonNull(scope);
		this.expiry = Objects.requireNonNull(expiry);
	}

	public AuthenticatedPrincipal getPrincipal() {
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
		return Instant.now().isAfter(this.expiry);
	}

}
