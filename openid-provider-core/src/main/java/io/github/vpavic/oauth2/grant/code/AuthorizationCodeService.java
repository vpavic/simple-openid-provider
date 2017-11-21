package io.github.vpavic.oauth2.grant.code;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.GeneralException;

public interface AuthorizationCodeService {

	AuthorizationCode create(AuthorizationCodeContext context);

	AuthorizationCodeContext consume(AuthorizationCode code) throws GeneralException;

}
