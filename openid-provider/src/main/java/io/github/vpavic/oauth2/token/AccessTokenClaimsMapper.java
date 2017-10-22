package io.github.vpavic.oauth2.token;

import java.util.Map;

public interface AccessTokenClaimsMapper {

	Map<String, Object> map(String principal);

}
