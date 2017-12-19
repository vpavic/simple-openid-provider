package io.github.vpavic.oauth2.grant.refresh;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

public class RefreshTokenContext implements Serializable {

	private final RefreshToken refreshToken;

	private final ClientID clientId;

	private final Subject subject;

	private final Scope scope;

	private final Instant expiry;

	public RefreshTokenContext(RefreshToken refreshToken, ClientID clientId, Subject subject, Scope scope,
			Instant expiry) {
		Objects.requireNonNull(refreshToken, "refreshToken must not be null");
		Objects.requireNonNull(clientId, "clientId must not be null");
		Objects.requireNonNull(subject, "subject must not be null");
		Objects.requireNonNull(scope, "scope must not be null");
		this.refreshToken = refreshToken;
		this.clientId = clientId;
		this.subject = subject;
		this.scope = scope;
		this.expiry = expiry;
	}

	public RefreshToken getRefreshToken() {
		return this.refreshToken;
	}

	public ClientID getClientId() {
		return this.clientId;
	}

	public Subject getSubject() {
		return this.subject;
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
