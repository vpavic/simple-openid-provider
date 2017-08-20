package io.github.vpavic.op.code;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.Nonce;

public class AuthorizationCodeContext implements Serializable {

	private final String principal;

	private final ClientID clientID;

	private final Scope scope;

	private final Instant authenticationTime;

	private final String sessionId;

	private final CodeChallenge codeChallenge;

	private final CodeChallengeMethod codeChallengeMethod;

	private final Nonce nonce;

	public AuthorizationCodeContext(String principal, ClientID clientID, Scope scope, Instant authenticationTime,
			String sessionId, CodeChallenge codeChallenge, CodeChallengeMethod codeChallengeMethod, Nonce nonce) {
		this.principal = Objects.requireNonNull(principal);
		this.clientID = Objects.requireNonNull(clientID);
		this.scope = Objects.requireNonNull(scope);
		this.authenticationTime = Objects.requireNonNull(authenticationTime);
		this.sessionId = Objects.requireNonNull(sessionId);
		this.codeChallenge = codeChallenge;
		this.codeChallengeMethod = codeChallengeMethod;
		this.nonce = nonce;
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

	public Instant getAuthenticationTime() {
		return this.authenticationTime;
	}

	public String getSessionId() {
		return this.sessionId;
	}

	public CodeChallenge getCodeChallenge() {
		return this.codeChallenge;
	}

	public CodeChallengeMethod getCodeChallengeMethod() {
		return this.codeChallengeMethod;
	}

	public Nonce getNonce() {
		return this.nonce;
	}

}
