package io.github.vpavic.op.oauth2.endsession;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.vpavic.op.oauth2.client.ClientRepository;

@Configuration
public class EndSessionConfiguration {

	private final OIDCProviderMetadata providerMetadata;

	private final ClientRepository clientRepository;

	public EndSessionConfiguration(OIDCProviderMetadata providerMetadata,
			ObjectProvider<ClientRepository> clientRepository) {
		this.providerMetadata = providerMetadata;
		this.clientRepository = clientRepository.getObject();
	}

	@Bean
	public EndSessionEndpoint endSessionEndpoint() {
		return new EndSessionEndpoint(this.providerMetadata, this.clientRepository);
	}

}
