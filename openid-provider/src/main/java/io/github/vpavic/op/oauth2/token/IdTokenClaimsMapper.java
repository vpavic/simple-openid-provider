package io.github.vpavic.op.oauth2.token;

import java.util.Map;

public interface IdTokenClaimsMapper {

	Map<String, Object> map(String principal);

}
