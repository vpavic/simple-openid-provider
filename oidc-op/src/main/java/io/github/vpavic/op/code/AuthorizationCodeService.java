 package io.github.vpavic.op.code;

 import java.util.Map;

 import com.nimbusds.oauth2.sdk.AuthorizationCode;

public interface AuthorizationCodeService {

	AuthorizationCode create(Map<String, ?> authContext);

	Map<String, ?> consume(AuthorizationCode code);

}
