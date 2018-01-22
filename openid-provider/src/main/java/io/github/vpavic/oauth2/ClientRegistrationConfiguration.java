package io.github.vpavic.oauth2;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.client.ClientService;
import io.github.vpavic.oauth2.client.DefaultClientService;
import io.github.vpavic.oauth2.endpoint.ClientRegistrationEndpoint;
import io.github.vpavic.oauth2.endpoint.ClientRegistrationHandler;

@Configuration
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
		DefaultClientService clientService = new DefaultClientService(this.clientRepository, registrationUriTemplate());
		clientService.setRefreshSecretOnUpdate(this.properties.getRegistration().isUpdateSecret());
		clientService.setRefreshAccessTokenOnUpdate(this.properties.getRegistration().isUpdateAccessToken());
		return clientService;
	}

	@Bean
	public ClientRegistrationEndpoint clientRegistrationEndpoint() {
		ClientRegistrationHandler handler = new ClientRegistrationHandler(this.clientRepository, clientService());
		handler.setAllowOpenRegistration(this.properties.getRegistration().isOpenRegistrationEnabled());
		handler.setApiAccessToken(this.properties.getRegistration().getApiAccessToken());
		return new ClientRegistrationEndpoint(handler);
	}

	private String registrationUriTemplate() {
		// @formatter:off
		return UriComponentsBuilder.fromHttpUrl(this.properties.getIssuer().getValue())
				.path(ClientRegistrationEndpoint.PATH_MAPPING)
				.path("/{id}")
				.build()
				.toUriString();
		// @formatter:on
	}

}
