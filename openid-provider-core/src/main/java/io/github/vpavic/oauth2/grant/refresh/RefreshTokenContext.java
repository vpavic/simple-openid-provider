package io.github.vpavic.oauth2.grant.refresh;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;

public class RefreshTokenContext implements Serializable {

	private final Subject subject;

	private final ClientID clientId;

	private final Scope scope;

	private final Instant expiry;

	public RefreshTokenContext(Subject subject, ClientID clientId, Scope scope, Instant expiry) {
		Objects.requireNonNull(subject, "subject must not be null");
		Objects.requireNonNull(clientId, "clientId must not be null");
		Objects.requireNonNull(scope, "scope must not be null");
		this.subject = subject;
		this.clientId = clientId;
		this.scope = scope;
		this.expiry = expiry;
	}

	public Subject getSubject() {
		return this.subject;
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
