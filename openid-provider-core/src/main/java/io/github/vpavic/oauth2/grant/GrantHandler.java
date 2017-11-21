package io.github.vpavic.oauth2.grant;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.token.Tokens;

public interface GrantHandler {

	Tokens grant(TokenRequest tokenRequest) throws GeneralException;

}
