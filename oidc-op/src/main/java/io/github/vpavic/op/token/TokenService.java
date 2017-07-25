package io.github.vpavic.op.token;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.springframework.security.core.userdetails.UserDetails;

public interface TokenService {

	AccessToken createAccessToken(AuthorizationRequest authRequest, UserDetails principal);

	RefreshToken createRefreshToken(AuthorizationRequest authRequest, UserDetails principal);

	JWT createIdToken(AuthenticationRequest authRequest, UserDetails principal);

}
