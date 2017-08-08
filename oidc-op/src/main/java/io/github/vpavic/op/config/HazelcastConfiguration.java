package io.github.vpavic.op.config;

import com.hazelcast.config.Config;
import com.hazelcast.config.MapAttributeConfig;
import com.hazelcast.config.MapIndexConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.hazelcast.HazelcastSessionRepository;
import org.springframework.session.hazelcast.PrincipalNameExtractor;

@Configuration
public class HazelcastConfiguration {

	@Bean
	public Config config() {
		// @formatter:off
		Config config = new Config("kaas")
				.setProperty("hazelcast.logging.type", "slf4j")
				.setProperty("hazelcast.phone.home.enabled", "false")
				.setProperty("hazelcast.rest.enabled", "true");
		// @formatter:on

		// @formatter:off
		MapAttributeConfig principalNameAttributeConfig = new MapAttributeConfig()
				.setName(HazelcastSessionRepository.PRINCIPAL_NAME_ATTRIBUTE)
				.setExtractor(PrincipalNameExtractor.class.getName());
		// @formatter:on

		// @formatter:off
		config.getMapConfig("spring:session:sessions")
				.addMapAttributeConfig(principalNameAttributeConfig)
				.addMapIndexConfig(new MapIndexConfig(HazelcastSessionRepository.PRINCIPAL_NAME_ATTRIBUTE, false));
		// @formatter:on

		return config;
	}

}
