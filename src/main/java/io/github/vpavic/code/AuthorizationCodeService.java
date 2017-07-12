package io.github.vpavic.code;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.token.Tokens;

public interface AuthorizationCodeService {

	AuthorizationCode create(Tokens tokens);

	Tokens consume(AuthorizationCode code);

}
