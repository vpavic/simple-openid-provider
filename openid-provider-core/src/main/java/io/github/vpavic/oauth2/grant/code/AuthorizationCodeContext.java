package io.github.vpavic.oauth2.grant.code;

import java.io.Serializable;
import java.net.URI;
import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;
import com.nimbusds.openid.connect.sdk.claims.SessionID;

public class AuthorizationCodeContext implements Serializable {

	private final Subject subject;

	private final ClientID clientId;

	private final URI redirectUri;

	private final Scope scope;

	private final Instant authenticationTime;

	private final ACR acr;

	private final AMR amr;

	private final SessionID sessionId;

	private final CodeChallenge codeChallenge;

	private final CodeChallengeMethod codeChallengeMethod;

	private final Nonce nonce;

	public AuthorizationCodeContext(Subject subject, ClientID clientId, URI redirectUri, Scope scope,
			Instant authenticationTime, ACR acr, AMR amr, SessionID sessionId, CodeChallenge codeChallenge,
			CodeChallengeMethod codeChallengeMethod, Nonce nonce) {
		Objects.requireNonNull(subject, "subject must not be null");
		Objects.requireNonNull(clientId, "clientId must not be null");
		Objects.requireNonNull(redirectUri, "redirectUri must not be null");
		Objects.requireNonNull(scope, "scope must not be null");
		Objects.requireNonNull(authenticationTime, "authenticationTime must not be null");
		Objects.requireNonNull(acr, "acr must not be null");
		Objects.requireNonNull(amr, "amr must not be null");
		Objects.requireNonNull(sessionId, "sessionId must not be null");
		this.subject = subject;
		this.clientId = clientId;
		this.redirectUri = redirectUri;
		this.scope = scope;
		this.authenticationTime = authenticationTime;
		this.acr = acr;
		this.amr = amr;
		this.sessionId = sessionId;
		this.codeChallenge = codeChallenge;
		this.codeChallengeMethod = codeChallengeMethod;
		this.nonce = nonce;
	}

	public Subject getSubject() {
		return this.subject;
	}

	public ClientID getClientId() {
		return this.clientId;
	}

	public URI getRedirectUri() {
		return this.redirectUri;
	}

	public Scope getScope() {
		return this.scope;
	}

	public Instant getAuthenticationTime() {
		return this.authenticationTime;
	}

	public ACR getAcr() {
		return this.acr;
	}

	public AMR getAmr() {
		return this.amr;
	}

	public SessionID getSessionId() {
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
