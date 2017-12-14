package io.github.vpavic.oauth2.token;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;

public final class RefreshTokenRequest {

	private final Subject subject;

	private final ClientID clientId;

	private final Scope scope;

	public RefreshTokenRequest(Subject subject, ClientID clientId, Scope scope) {
		Objects.requireNonNull(subject, "subject must not be null");
		Objects.requireNonNull(clientId, "clientId must not be null");
		Objects.requireNonNull(scope, "scope must not be null");
		this.subject = subject;
		this.clientId = clientId;
		this.scope = scope;
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

}
