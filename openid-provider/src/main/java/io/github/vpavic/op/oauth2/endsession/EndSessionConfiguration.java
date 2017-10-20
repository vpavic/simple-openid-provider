package io.github.vpavic.op.oauth2.endsession;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.vpavic.op.config.OpenIdProviderProperties;
import io.github.vpavic.op.oauth2.client.ClientRepository;

@Configuration
public class EndSessionConfiguration {

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	public EndSessionConfiguration(OpenIdProviderProperties properties,
			ObjectProvider<ClientRepository> clientRepository) {
		this.properties = properties;
		this.clientRepository = clientRepository.getObject();
	}

	@Bean
	public EndSessionEndpoint endSessionEndpoint() {
		return new EndSessionEndpoint(this.properties, this.clientRepository);
	}

}
