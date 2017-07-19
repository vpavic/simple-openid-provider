package io.github.vpavic.op.token;

import java.security.Principal;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

public interface TokenService {

	Tokens createTokens(AuthorizationRequest request, Principal principal);

	OIDCTokens createTokens(AuthenticationRequest request, Principal principal);

}
