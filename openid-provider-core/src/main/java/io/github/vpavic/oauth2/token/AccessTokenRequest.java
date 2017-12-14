package io.github.vpavic.oauth2.token;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

public final class AccessTokenRequest {

	private final Subject subject;

	private final OIDCClientInformation client;

	private final Scope scope;

	public AccessTokenRequest(Subject subject, OIDCClientInformation client, Scope scope) {
		Objects.requireNonNull(subject, "subject must not be null");
		Objects.requireNonNull(client, "client must not be null");
		Objects.requireNonNull(scope, "scope must not be null");
		this.subject = subject;
		this.client = client;
		this.scope = scope;
	}

	public Subject getSubject() {
		return this.subject;
	}

	public OIDCClientInformation getClient() {
		return this.client;
	}

	public Scope getScope() {
		return this.scope;
	}

}
