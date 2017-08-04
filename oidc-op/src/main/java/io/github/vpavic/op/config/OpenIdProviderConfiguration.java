package io.github.vpavic.op.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(OpenIdProviderProperties.class)
public class OpenIdProviderConfiguration {

}
