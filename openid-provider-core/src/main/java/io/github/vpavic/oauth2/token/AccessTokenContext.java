package io.github.vpavic.oauth2.token;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;

public final class AccessTokenContext {

	private final Scope scope;

	private final Subject subject;

	public AccessTokenContext(Scope scope, Subject subject) {
		Objects.requireNonNull(scope, "scope must not be null");
		Objects.requireNonNull(subject, "subject must not be null");
		this.scope = scope;
		this.subject = subject;
	}

	public Scope getScope() {
		return this.scope;
	}

	public Subject getSubject() {
		return this.subject;
	}

}
