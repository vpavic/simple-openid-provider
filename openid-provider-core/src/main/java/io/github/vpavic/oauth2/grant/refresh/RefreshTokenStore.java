package io.github.vpavic.oauth2.grant.refresh;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

public interface RefreshTokenStore {

	void save(RefreshToken refreshToken, RefreshTokenContext context);

	RefreshTokenContext load(RefreshToken refreshToken) throws GeneralException;

	void revoke(RefreshToken refreshToken);

}