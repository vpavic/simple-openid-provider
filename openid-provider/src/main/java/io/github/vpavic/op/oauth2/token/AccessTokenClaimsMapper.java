package io.github.vpavic.op.oauth2.token;

import java.util.Map;

public interface AccessTokenClaimsMapper {

	Map<String, Object> map(String principal);

}
