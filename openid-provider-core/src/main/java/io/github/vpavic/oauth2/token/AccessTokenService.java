package io.github.vpavic.oauth2.token;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.token.AccessToken;

public interface AccessTokenService {

	AccessToken createAccessToken(AccessTokenRequest accessTokenRequest);

	AccessTokenContext resolveAccessTokenContext(AccessToken accessToken) throws GeneralException;

}
