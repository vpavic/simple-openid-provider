package io.github.vpavic.op.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * OpenID Provider configuration.
 *
 * @author Vedran Pavic
 */
@Configuration
@EnableConfigurationProperties(OpenIdProviderProperties.class)
public class OpenIdProviderConfiguration {

}
