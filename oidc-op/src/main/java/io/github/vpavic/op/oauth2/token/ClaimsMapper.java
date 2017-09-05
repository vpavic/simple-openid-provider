package io.github.vpavic.op.oauth2.token;

import java.util.Map;

public interface ClaimsMapper {

	Map<String, Object> map(String principal);

}
