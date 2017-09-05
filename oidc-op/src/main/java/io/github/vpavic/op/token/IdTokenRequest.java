package io.github.vpavic.op.token;

import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;

import io.github.vpavic.op.userinfo.UserInfoMapper;

public final class IdTokenRequest {

	private final String principal;

	private final ClientID clientID;

	private final Scope scope;

	private final Instant authenticationTime;

	private final ACR acr;

	private final AMR amr;

	private final String sessionId;

	private final Nonce nonce;

	private final AccessToken accessToken;

	private final AuthorizationCode code;

	private final UserInfoMapper userInfoMapper;

	public IdTokenRequest(String principal, ClientID clientID, Scope scope, Instant authenticationTime, ACR acr,
			AMR amr, String sessionId, Nonce nonce, AccessToken accessToken, AuthorizationCode code,
			UserInfoMapper userInfoMapper) {
		Objects.requireNonNull(principal, "principal must not be null");
		Objects.requireNonNull(clientID, "clientID must not be null");
		Objects.requireNonNull(scope, "scope must not be null");
		Objects.requireNonNull(authenticationTime, "authenticationTime must not be null");
		Objects.requireNonNull(acr, "acr must not be null");
		Objects.requireNonNull(amr, "amr must not be null");

		this.principal = principal;
		this.clientID = clientID;
		this.scope = scope;
		this.authenticationTime = authenticationTime;
		this.acr = acr;
		this.amr = amr;
		this.sessionId = sessionId;
		this.nonce = nonce;
		this.accessToken = accessToken;
		this.code = code;
		this.userInfoMapper = userInfoMapper;
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

	public ACR getAcr() {
		return this.acr;
	}

	public AMR getAmr() {
		return this.amr;
	}

	public String getSessionId() {
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

	public UserInfoMapper getUserInfoMapper() {
		return this.userInfoMapper;
	}

}
