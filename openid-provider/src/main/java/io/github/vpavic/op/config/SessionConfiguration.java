package io.github.vpavic.op.config;

import javax.annotation.PostConstruct;

import com.hazelcast.config.Config;
import com.hazelcast.config.MapAttributeConfig;
import com.hazelcast.config.MapConfig;
import com.hazelcast.config.MapIndexConfig;
import com.hazelcast.core.HazelcastInstance;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.session.HazelcastSessionProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.hazelcast.HazelcastSessionRepository;
import org.springframework.session.hazelcast.PrincipalNameExtractor;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

@Configuration
public class SessionConfiguration {

	private final HazelcastSessionProperties sessionProperties;

	private final HazelcastInstance hazelcastInstance;

	public SessionConfiguration(HazelcastSessionProperties sessionProperties,
			ObjectProvider<HazelcastInstance> hazelcastInstance) {
		this.sessionProperties = sessionProperties;
		this.hazelcastInstance = hazelcastInstance.getObject();
	}

	@PostConstruct
	public void init() {
		Config config = this.hazelcastInstance.getConfig();
		String mapName = this.sessionProperties.getMapName();
		MapConfig mapConfig = config.getMapConfigOrNull(mapName);

		if (mapConfig == null) {
			// @formatter:off
			MapAttributeConfig principalNameAttributeConfig = new MapAttributeConfig()
					.setName(HazelcastSessionRepository.PRINCIPAL_NAME_ATTRIBUTE)
					.setExtractor(PrincipalNameExtractor.class.getName());
			// @formatter:on

			MapIndexConfig principalNameIndexConfig = new MapIndexConfig(
					HazelcastSessionRepository.PRINCIPAL_NAME_ATTRIBUTE, false);

			// @formatter:off
			mapConfig = new MapConfig(mapName)
					.addMapAttributeConfig(principalNameAttributeConfig)
					.addMapIndexConfig(principalNameIndexConfig);
			// @formatter:on

			config.addMapConfig(mapConfig);
		}
	}

	@Bean
	public CookieSerializer cookieSerializer() {
		DefaultCookieSerializer cookieSerializer = new DefaultCookieSerializer();
		cookieSerializer.setCookieName("sid");
		cookieSerializer.setUseHttpOnlyCookie(false);
		return cookieSerializer;
	}

}
