package io.github.vpavic.op.token;

import java.time.Instant;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.Nonce;

import io.github.vpavic.op.userinfo.UserInfoMapper;

public interface TokenService {

	AccessToken createAccessToken(String principal, ClientID clientID, Scope scope, ClaimsMapper claimsMapper);

	RefreshToken createRefreshToken(String principal, ClientID clientID, Scope scope);

	JWT createIdToken(String principal, ClientID clientID, Scope scope, Instant authenticationTime, String sessionId,
			Nonce nonce, AccessToken accessToken, AuthorizationCode code, UserInfoMapper userInfoMapper);

}
