package io.github.vpavic.op.code;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.springframework.stereotype.Service;

@Service
public class MapAuthorizationCodeService implements AuthorizationCodeService {

	private final ConcurrentMap<String, AuthorizationCodeContext> store = new ConcurrentHashMap<>();

	@Override
	public AuthorizationCode create(AuthorizationCodeContext context) {
		AuthorizationCode code = new AuthorizationCode();
		this.store.put(code.getValue(), context);
		return code;
	}

	@Override
	public AuthorizationCodeContext consume(AuthorizationCode code) {
		AuthorizationCodeContext context = this.store.remove(code.getValue());

		if (context == null) {
			throw new IllegalArgumentException("Invalid code " + code);
		}

		return context;
	}

}
