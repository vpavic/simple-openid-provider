package io.github.vpavic.oauth2.token;

import com.nimbusds.jwt.JWT;

public interface IdTokenService {

	JWT createIdToken(IdTokenRequest idTokenRequest);

}
