package io.github.vpavic.oauth2;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.client.ClientService;
import io.github.vpavic.oauth2.client.DefaultClientService;
import io.github.vpavic.oauth2.endpoint.ClientRegistrationEndpoint;

@Configuration
@Import(ClientRegistrationSecurityConfiguration.class)
public class ClientRegistrationConfiguration {

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	public ClientRegistrationConfiguration(OpenIdProviderProperties properties,
			ObjectProvider<ClientRepository> clientRepository) {
		this.properties = properties;
		this.clientRepository = clientRepository.getObject();
	}

	@Bean
	public ClientService clientService() {
		DefaultClientService clientService = new DefaultClientService(this.properties.getIssuer(),
				this.clientRepository);
		clientService.setRefreshSecretOnUpdate(this.properties.getRegistration().isUpdateSecret());
		clientService.setRefreshSecretOnUpdate(this.properties.getRegistration().isUpdateAccessToken());
		return clientService;
	}

	@Bean
	public ClientRegistrationEndpoint clientRegistrationEndpoint() {
		ClientRegistrationEndpoint endpoint = new ClientRegistrationEndpoint(this.clientRepository, clientService());
		endpoint.setAllowOpenRegistration(this.properties.getRegistration().isOpenRegistrationEnabled());
		endpoint.setApiAccessToken(this.properties.getRegistration().getApiAccessToken());
		return endpoint;
	}

}
