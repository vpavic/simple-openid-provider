package io.github.vpavic.oauth2;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import io.github.vpavic.oauth2.client.ClientRegistrationEndpoint;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.client.ClientService;
import io.github.vpavic.oauth2.client.DefaultClientService;

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
		DefaultClientService clientService = new DefaultClientService(this.properties.getIssuer(), this.clientRepository);
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

	@Order(-2)
	@Configuration
	public static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.antMatcher(ClientRegistrationEndpoint.PATH_MAPPING + "/**")
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.csrf()
					.disable()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			// @formatter:on
		}

	}

}
