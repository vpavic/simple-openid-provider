package io.github.vpavic.oauth2.grant.code;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.commons.lang3.StringUtils;

/**
 * Hazelcast implementation of {@link AuthorizationCodeService}.
 *
 * By default uses map named {@code op.authorizationCodes} and code lifetime of 5 minutes. These can be customize using
 * {@link #setMapName(String)} and {@link #setCodeLifetime(Duration)}, respectively.
 */
public class HazelcastAuthorizationCodeService implements AuthorizationCodeService {

	private static final String DEFAULT_MAP_NAME = "op.authorizationCodes";

	private static final Duration DEFAULT_CODE_LIFETIME = Duration.ofMinutes(5);

	private final HazelcastInstance hazelcastInstance;

	private String mapName = DEFAULT_MAP_NAME;

	private Duration codeLifetime = DEFAULT_CODE_LIFETIME;

	private IMap<String, AuthorizationCodeContext> codes;

	public HazelcastAuthorizationCodeService(HazelcastInstance hazelcastInstance) {
		Objects.requireNonNull(hazelcastInstance, "hazelcastInstance must not be null");
		this.hazelcastInstance = hazelcastInstance;
	}

	@PostConstruct
	public void init() {
		this.codes = this.hazelcastInstance.getMap(this.mapName);
	}

	@Override
	public AuthorizationCode create(AuthorizationCodeContext context) {
		Objects.requireNonNull(context, "context must not be null");
		AuthorizationCode code = new AuthorizationCode();
		this.codes.put(code.getValue(), context, this.codeLifetime.getSeconds(), TimeUnit.SECONDS);
		return code;
	}

	@Override
	public AuthorizationCodeContext consume(AuthorizationCode code) throws GeneralException {
		Objects.requireNonNull(code, "code must not be null");
		AuthorizationCodeContext context = this.codes.remove(code.getValue());
		if (context == null) {
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}
		return context;
	}

	public void setMapName(String mapName) {
		Objects.requireNonNull(mapName, "mapName must not be null");
		if (StringUtils.isBlank(mapName)) {
			throw new IllegalArgumentException("mapName must not be empty");
		}
		this.mapName = mapName;
	}

	public void setCodeLifetime(Duration codeLifetime) {
		Objects.requireNonNull(codeLifetime, "codeLifetime must not be null");
		this.codeLifetime = codeLifetime;
	}

}
