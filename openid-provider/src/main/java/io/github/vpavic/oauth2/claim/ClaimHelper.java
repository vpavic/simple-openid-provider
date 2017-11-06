package io.github.vpavic.oauth2.claim;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

public final class ClaimHelper {

	private ClaimHelper() {
	}

	public static Set<String> resolveClaims(Scope scope, Map<Scope.Value, List<String>> scopeClaims) {
		Set<String> claims = new HashSet<>();
		for (Scope.Value scopeValue : scope) {
			if (scopeValue instanceof OIDCScopeValue) {
				claims.addAll(((OIDCScopeValue) scopeValue).getClaimNames());
			}
			if (scopeClaims.containsKey(scopeValue)) {
				claims.addAll(scopeClaims.get(scopeValue));
			}
		}
		return claims;
	}

}
