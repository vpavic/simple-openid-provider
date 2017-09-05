package io.github.vpavic.op.oauth2.token;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.Scope;

public final class AccessTokenRequest {

	private final String principal;

	private final Scope scope;

	private final ClaimsMapper claimsMapper;

	public AccessTokenRequest(String principal, Scope scope, ClaimsMapper claimsMapper) {
		Objects.requireNonNull(principal, "principal must not be null");
		Objects.requireNonNull(scope, "scope must not be null");

		this.principal = principal;
		this.scope = scope;
		this.claimsMapper = claimsMapper;
	}

	public String getPrincipal() {
		return this.principal;
	}

	public Scope getScope() {
		return this.scope;
	}

	public ClaimsMapper getClaimsMapper() {
		return this.claimsMapper;
	}

}
