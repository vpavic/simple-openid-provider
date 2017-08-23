package io.github.vpavic.op.token;

import java.util.Collections;
import java.util.Map;

import org.springframework.stereotype.Component;

@Component
public class NullClaimsMapper implements ClaimsMapper {

	@Override
	public Map<String, Object> map(String principal) {
		return Collections.emptyMap();
	}

}
