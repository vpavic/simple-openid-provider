package io.github.vpavic.op.config;

import com.hazelcast.config.Config;
import com.hazelcast.config.JoinConfig;
import com.hazelcast.config.MapAttributeConfig;
import com.hazelcast.config.MapIndexConfig;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.hazelcast.HazelcastSessionRepository;
import org.springframework.session.hazelcast.PrincipalNameExtractor;

@Configuration
@EnableConfigurationProperties(HazelcastProperties.class)
public class HazelcastConfiguration {

	private final HazelcastProperties hazelcastProperties;

	public HazelcastConfiguration(HazelcastProperties hazelcastProperties) {
		this.hazelcastProperties = hazelcastProperties;
	}

	@Bean
	public Config config() {
		// @formatter:off
		Config config = new Config("op")
				.setProperty("hazelcast.jmx", "true")
				.setProperty("hazelcast.logging.type", "slf4j")
				.setProperty("hazelcast.phone.home.enabled", "false");
		// @formatter:on

		// @formatter:off
		config.getGroupConfig()
				.setName(this.hazelcastProperties.getGroupName())
				.setPassword(this.hazelcastProperties.getGroupPassword());
		// @formatter:on

		// @formatter:off
		JoinConfig joinConfig = config.getNetworkConfig()
				.setPort(this.hazelcastProperties.getPort())
				.getJoin();
		// @formatter:on

		if (!"multicast".equals(this.hazelcastProperties.getMembers())) {
			// @formatter:off
			joinConfig.getMulticastConfig()
					.setEnabled(false);
			// @formatter:on

			if (this.hazelcastProperties.getMembers() != null) {
				// @formatter:off
				joinConfig.getTcpIpConfig()
						.setEnabled(true)
						.addMember(this.hazelcastProperties.getMembers());
				// @formatter:on
			}
		}

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
