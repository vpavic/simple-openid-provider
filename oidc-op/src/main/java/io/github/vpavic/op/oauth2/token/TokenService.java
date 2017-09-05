package io.github.vpavic.op.oauth2.token;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

public interface TokenService {

	AccessToken createAccessToken(AccessTokenRequest accessTokenRequest);

	RefreshToken createRefreshToken(RefreshTokenRequest refreshTokenRequest);

	JWT createIdToken(IdTokenRequest idTokenRequest);

}
