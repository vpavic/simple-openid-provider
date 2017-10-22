package io.github.vpavic.oauth2.token;

import java.time.Instant;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import io.github.vpavic.oauth2.userinfo.UserInfoMapper;

public final class IdTokenRequest {

	private final String principal;

	private final OIDCClientInformation client;

	private final Scope scope;

	private final Instant authenticationTime;

	private final ACR acr;

	private final AMR amr;

	private final String sessionId;

	private final Nonce nonce;

	private final AccessToken accessToken;

	private final AuthorizationCode code;

	private final IdTokenClaimsMapper idTokenClaimsMapper;

	private final UserInfoMapper userInfoMapper;

	public IdTokenRequest(String principal, OIDCClientInformation client, Scope scope, Instant authenticationTime,
			ACR acr, AMR amr, IdTokenClaimsMapper idTokenClaimsMapper, String sessionId, Nonce nonce,
			AccessToken accessToken, AuthorizationCode code, UserInfoMapper userInfoMapper) {
		Objects.requireNonNull(principal, "principal must not be null");
		Objects.requireNonNull(client, "client must not be null");
		Objects.requireNonNull(scope, "scope must not be null");
		Objects.requireNonNull(authenticationTime, "authenticationTime must not be null");
		Objects.requireNonNull(acr, "acr must not be null");
		Objects.requireNonNull(amr, "amr must not be null");
		Objects.requireNonNull(idTokenClaimsMapper, "idTokenClaimsMapper must not be null");

		this.principal = principal;
		this.client = client;
		this.scope = scope;
		this.authenticationTime = authenticationTime;
		this.acr = acr;
		this.amr = amr;
		this.idTokenClaimsMapper = idTokenClaimsMapper;
		this.sessionId = sessionId;
		this.nonce = nonce;
		this.accessToken = accessToken;
		this.code = code;
		this.userInfoMapper = userInfoMapper;
	}

	public String getPrincipal() {
		return this.principal;
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

	public IdTokenClaimsMapper getIdTokenClaimsMapper() {
		return this.idTokenClaimsMapper;
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
