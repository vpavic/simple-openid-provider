package io.github.vpavic.op.oauth2.discovery;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class DiscoveryConfiguration {

	private final OIDCProviderMetadata providerMetadata;

	public DiscoveryConfiguration(OIDCProviderMetadata providerMetadata) {
		this.providerMetadata = providerMetadata;
	}

	@Bean
	public DiscoveryEndpoint discoveryEndpoint() {
		return new DiscoveryEndpoint(this.providerMetadata);
	}

	@Order(92)
	@Configuration
	static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.antMatcher(DiscoveryEndpoint.PATH_MAPPING)
				.authorizeRequests()
					.anyRequest().permitAll();
			// @formatter:on
		}

	}

}
