package io.github.vpavic.oauth2.grant;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.token.Tokens;

public interface GrantHandler {

	Tokens grant(AuthorizationGrant authorizationGrant, Scope scope, ClientAuthentication clientAuthentication)
			throws GeneralException;

}
