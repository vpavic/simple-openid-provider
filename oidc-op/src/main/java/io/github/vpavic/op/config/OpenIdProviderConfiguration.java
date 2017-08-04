package io.github.vpavic.op.config;

import java.util.Collections;

import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.id.Audience;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.vpavic.op.client.ClientRepository;

@Configuration
@EnableConfigurationProperties(OpenIdProviderProperties.class)
public class OpenIdProviderConfiguration {

	private final OpenIdProviderProperties properties;

	public OpenIdProviderConfiguration(OpenIdProviderProperties properties) {
		this.properties = properties;
	}

	@Bean
	public ClientAuthenticationVerifier<ClientRepository> clientAuthenticationVerifier() {
		return new ClientAuthenticationVerifier<>(new ClientRepositoryClientCredentialsSelector(), null,
				Collections.singleton(new Audience(this.properties.getIssuer())));
	}

}
