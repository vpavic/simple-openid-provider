package io.github.vpavic.oauth2.code.hazelcast;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;

import io.github.vpavic.oauth2.code.AuthorizationCodeContext;
import io.github.vpavic.oauth2.code.AuthorizationCodeService;

public class HazelcastAuthorizationCodeService implements AuthorizationCodeService {

	private static final String CODES_MAP = "op.authorizationCodes";

	private final IMap<String, AuthorizationCodeContext> codes;

	private Duration codeLifetime = Duration.ofMinutes(5);

	public HazelcastAuthorizationCodeService(HazelcastInstance hazelcastInstance) {
		Objects.requireNonNull(hazelcastInstance, "hazelcastInstance must not be null");

		this.codes = hazelcastInstance.getMap(CODES_MAP);
	}

	@Override
	public AuthorizationCode create(AuthorizationCodeContext context) {
		AuthorizationCode code = new AuthorizationCode();
		this.codes.put(code.getValue(), context, this.codeLifetime.getSeconds(), TimeUnit.SECONDS);

		return code;
	}

	@Override
	public AuthorizationCodeContext consume(AuthorizationCode code) throws GeneralException {
		AuthorizationCodeContext context = this.codes.remove(code.getValue());

		if (context == null) {
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}

		return context;
	}

	public void setCodeLifetime(Duration codeLifetime) {
		this.codeLifetime = codeLifetime;
	}

}
