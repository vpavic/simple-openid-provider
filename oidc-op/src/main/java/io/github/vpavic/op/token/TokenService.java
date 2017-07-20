package io.github.vpavic.op.token;

import java.security.Principal;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

public interface TokenService {

	AccessToken createAccessToken(AuthenticationRequest authRequest, Principal principal);

	RefreshToken createRefreshToken();

	JWT createIdToken(AuthenticationRequest authRequest, Principal principal);

}
