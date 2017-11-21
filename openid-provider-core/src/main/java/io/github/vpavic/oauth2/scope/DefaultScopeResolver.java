package io.github.vpavic.oauth2.scope;

import java.util.Collections;
import java.util.List;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

public class DefaultScopeResolver implements ScopeResolver {

	private List<Scope.Value> supportedScopes = Collections.singletonList(OIDCScopeValue.OPENID);

	@Override
	public Scope resolve(Subject subject, Scope requestedScope, OIDCClientMetadata clientMetadata) throws GeneralException {
		requestedScope.retainAll(this.supportedScopes);
		Scope registeredScope = clientMetadata.getScope();
		Scope resolvedScope;

		if (registeredScope == null || registeredScope.isEmpty()) {
			resolvedScope = requestedScope;
		}
		else {
			resolvedScope = new Scope();

			for (Scope.Value scope : requestedScope) {
				if (registeredScope.contains(scope)) {
					resolvedScope.add(scope);
				}
			}
		}

		if (resolvedScope.isEmpty()) {
			throw new GeneralException(OAuth2Error.INVALID_SCOPE);
		}

		return resolvedScope;
	}

	public void setSupportedScopes(List<Scope.Value> supportedScopes) {
		this.supportedScopes = supportedScopes;
	}

}
