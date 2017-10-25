package io.github.vpavic.oauth2.client;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.vpavic.oauth2.OpenIdProviderProperties;

public class DefaultClientService implements ClientService {

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	public DefaultClientService(OpenIdProviderProperties properties, ClientRepository clientRepository) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");

		this.properties = properties;
		this.clientRepository = clientRepository;
	}

	@Override
	@Transactional
	public OIDCClientInformation create(OIDCClientMetadata metadata) {
		metadata.applyDefaults();
		ClientID clientId = new ClientID(UUID.randomUUID().toString());
		Instant issueDate = Instant.now();
		Secret secret = null;

		if (!ClientAuthenticationMethod.NONE.equals(metadata.getTokenEndpointAuthMethod())) {
			secret = new Secret();
		}

		URI registrationUri = UriComponentsBuilder.fromHttpUrl(this.properties.getIssuer().getValue())
				.path("/oauth2/register/{id}").build(clientId.getValue());
		BearerAccessToken accessToken = new BearerAccessToken();
		OIDCClientInformation client = new OIDCClientInformation(clientId, Date.from(issueDate),
				metadata, secret, registrationUri, accessToken);
		this.clientRepository.save(client);

		return client;
	}

	@Override
	@Transactional
	public OIDCClientInformation update(ClientID id, OIDCClientMetadata metadata)
			throws InvalidClientException {
		OIDCClientInformation client = this.clientRepository.findById(id);

		if (client == null) {
			throw InvalidClientException.BAD_ID;
		}

		metadata.applyDefaults();
		Secret secret = null;

		if (!ClientAuthenticationMethod.NONE.equals(metadata.getTokenEndpointAuthMethod())) {
			secret = this.properties.getRegistration().isUpdateSecret() ? new Secret() : client.getSecret();
		}

		BearerAccessToken accessToken = this.properties.getRegistration().isUpdateAccessToken()
				? new BearerAccessToken()
				: client.getRegistrationAccessToken();

		client = new OIDCClientInformation(id, client.getIDIssueDate(), metadata,
				secret, client.getRegistrationURI(), accessToken);
		this.clientRepository.save(client);

		return client;
	}

}
