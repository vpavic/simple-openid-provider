package io.github.vpavic.oauth2.token;

import com.nimbusds.oauth2.sdk.token.RefreshToken;

public interface RefreshTokenService {

	RefreshToken createRefreshToken(RefreshTokenRequest refreshTokenRequest);

}
