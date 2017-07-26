package io.github.vpavic.op.code;

import com.nimbusds.oauth2.sdk.AuthorizationCode;

public interface AuthorizationCodeService {

	AuthorizationCode create(AuthorizationCodeContext context);

	AuthorizationCodeContext consume(AuthorizationCode code);

}
