package io.github.vpavic.op.code;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.springframework.stereotype.Service;

@Service
public class MapAuthorizationCodeService implements AuthorizationCodeService {

	private final ConcurrentMap<String, Map<String, ?>> store = new ConcurrentHashMap<>();

	@Override
	public AuthorizationCode create(Map<String, ?> authContext) {
		AuthorizationCode code = new AuthorizationCode();
		this.store.put(code.getValue(), authContext);
		return code;
	}

	@Override
	public Map<String, ?> consume(AuthorizationCode code) {
		Map<String, ?> authContext = this.store.remove(code.getValue());

		if (authContext == null) {
			throw new IllegalArgumentException("Invalid code " + code);
		}

		return authContext;
	}

}
