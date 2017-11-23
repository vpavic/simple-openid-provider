package io.github.vpavic.oauth2;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import io.github.vpavic.oauth2.config.OpenIdProviderWebMvcConfiguration;

/**
 * OpenID Provider configuration.
 *
 * @author Vedran Pavic
 */
@Configuration
@EnableConfigurationProperties(OpenIdProviderProperties.class)
@Import({ OpenIdProviderWebMvcConfiguration.class, CoreConfiguration.class, DiscoveryConfiguration.class,
		ClientRegistrationConfiguration.class, LogoutConfiguration.class })
public class OpenIdProviderConfiguration {

}
