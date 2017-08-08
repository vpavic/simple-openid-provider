package io.github.vpavic.op.code;

import java.util.concurrent.TimeUnit;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.springframework.stereotype.Service;

@Service
public class HazelcastAuthorizationCodeService implements AuthorizationCodeService {

	private final IMap<String, AuthorizationCodeContext> store;

	public HazelcastAuthorizationCodeService(HazelcastInstance hazelcastInstance) {
		this.store = hazelcastInstance.getMap("authorizationCodes");
	}

	@Override
	public AuthorizationCode create(AuthorizationCodeContext context) {
		AuthorizationCode code = new AuthorizationCode();
		this.store.put(code.getValue(), context, 10, TimeUnit.MINUTES);
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
