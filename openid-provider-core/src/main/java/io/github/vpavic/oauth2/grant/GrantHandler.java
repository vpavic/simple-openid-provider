package io.github.vpavic.oauth2.grant;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.token.Tokens;

public interface GrantHandler {

	Class<? extends AuthorizationGrant> grantType();

	Tokens grant(TokenRequest tokenRequest) throws GeneralException;

	default boolean supports(AuthorizationGrant grant) {
		return grantType().isInstance(grant);
	}

}
