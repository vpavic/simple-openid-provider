package io.github.vpavic.oauth2.token;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;

public class AuthorizationCodeContext implements Serializable {

	private final String principal;

	private final ClientID clientId;

	private final Scope scope;

	private final Instant authenticationTime;

	private final ACR acr;

	private final AMR amr;

	private final String sessionId;

	private final CodeChallenge codeChallenge;

	private final CodeChallengeMethod codeChallengeMethod;

	private final Nonce nonce;

	public AuthorizationCodeContext(String principal, ClientID clientId, Scope scope, Instant authenticationTime,
			ACR acr, AMR amr, String sessionId, CodeChallenge codeChallenge, CodeChallengeMethod codeChallengeMethod,
			Nonce nonce) {
		Objects.requireNonNull(principal, "principal must not be null");
		Objects.requireNonNull(clientId, "clientId must not be null");
		Objects.requireNonNull(scope, "scope must not be null");
		Objects.requireNonNull(authenticationTime, "authenticationTime must not be null");
		Objects.requireNonNull(acr, "acr must not be null");
		Objects.requireNonNull(amr, "amr must not be null");
		Objects.requireNonNull(sessionId, "sessionId must not be null");

		this.principal = principal;
		this.clientId = clientId;
		this.scope = scope;
		this.authenticationTime = authenticationTime;
		this.acr = acr;
		this.amr = amr;
		this.sessionId = sessionId;
		this.codeChallenge = codeChallenge;
		this.codeChallengeMethod = codeChallengeMethod;
		this.nonce = nonce;
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

	public Instant getAuthenticationTime() {
		return this.authenticationTime;
	}

	public ACR getAcr() {
		return this.acr;
	}

	public AMR getAmr() {
		return this.amr;
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
