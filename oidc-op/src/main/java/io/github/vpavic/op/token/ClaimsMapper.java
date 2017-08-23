package io.github.vpavic.op.token;

import java.util.Map;

public interface ClaimsMapper {

	Map<String, Object> map(String principal);

}
