package io.github.vpavic.oauth2.token;

import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

public final class IdTokenRequest {

	private final Subject subject;

	private final OIDCClientInformation client;

	private final Scope scope;

	private final Instant authenticationTime;

	private final ACR acr;

	private final AMR amr;

	private final SessionID sessionId;

	private final Nonce nonce;

	private final AccessToken accessToken;

	private final AuthorizationCode code;

	public IdTokenRequest(Subject subject, OIDCClientInformation client, Scope scope, Instant authenticationTime,
			ACR acr, AMR amr, SessionID sessionId, Nonce nonce, AccessToken accessToken, AuthorizationCode code) {
		Objects.requireNonNull(subject, "subject must not be null");
		Objects.requireNonNull(client, "client must not be null");
		Objects.requireNonNull(scope, "scope must not be null");
		Objects.requireNonNull(authenticationTime, "authenticationTime must not be null");
		Objects.requireNonNull(acr, "acr must not be null");
		Objects.requireNonNull(amr, "amr must not be null");

		if (!scope.contains(OIDCScopeValue.OPENID)) {
			throw new IllegalArgumentException("Scope '" + OIDCScopeValue.OPENID + "' is required");
		}

		this.subject = subject;
		this.client = client;
		this.scope = scope;
		this.authenticationTime = authenticationTime;
		this.acr = acr;
		this.amr = amr;
		this.sessionId = sessionId;
		this.nonce = nonce;
		this.accessToken = accessToken;
		this.code = code;
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

	public Nonce getNonce() {
		return this.nonce;
	}

	public AccessToken getAccessToken() {
		return this.accessToken;
	}

	public AuthorizationCode getCode() {
		return this.code;
	}

}
