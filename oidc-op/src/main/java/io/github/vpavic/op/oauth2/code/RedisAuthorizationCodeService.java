package io.github.vpavic.op.oauth2.code;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.stereotype.Service;

import io.github.vpavic.op.config.OpenIdProviderProperties;

@Service
public class RedisAuthorizationCodeService implements AuthorizationCodeService {

	private static final String PREFIX = "op:codes:";

	private final OpenIdProviderProperties properties;

	private final RedisOperations<String, Object> redisOperations;

	public RedisAuthorizationCodeService(OpenIdProviderProperties properties,
			RedisConnectionFactory redisConnectionFactory) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(redisConnectionFactory, "redisConnectionFactory must not be null");

		this.properties = properties;
		this.redisOperations = createRedisOperations(redisConnectionFactory);
	}

	@Override
	public AuthorizationCode create(AuthorizationCodeContext context) {
		AuthorizationCode code = new AuthorizationCode();
		this.redisOperations.boundValueOps(getKey(code)).set(context, this.properties.getCode().getLifetime(),
				TimeUnit.SECONDS);

		return code;
	}

	@Override
	public AuthorizationCodeContext consume(AuthorizationCode code) throws GeneralException {
		String key = getKey(code);
		AuthorizationCodeContext context = (AuthorizationCodeContext) this.redisOperations.boundValueOps(key).get();

		if (context == null) {
			throw new GeneralException(OAuth2Error.INVALID_GRANT);
		}

		this.redisOperations.delete(key);

		return context;
	}

	private static String getKey(AuthorizationCode code) {
		return PREFIX + code.getValue();
	}

	private RedisOperations<String, Object> createRedisOperations(RedisConnectionFactory connectionFactory) {
		RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
		redisTemplate.setConnectionFactory(connectionFactory);
		redisTemplate.setKeySerializer(new StringRedisSerializer());
		redisTemplate.setDefaultSerializer(new JdkSerializationRedisSerializer(getClass().getClassLoader()));
		redisTemplate.afterPropertiesSet();

		return redisTemplate;
	}

}
