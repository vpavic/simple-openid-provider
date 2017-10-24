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
	public OIDCClientInformation create(OIDCClientMetadata clientMetadata) {
		clientMetadata.applyDefaults();
		ClientID clientId = new ClientID(UUID.randomUUID().toString());
		Instant issueDate = Instant.now();
		Secret secret = null;

		if (!ClientAuthenticationMethod.NONE.equals(clientMetadata.getTokenEndpointAuthMethod())) {
			secret = new Secret();
		}

		URI registrationUri = UriComponentsBuilder.fromHttpUrl(this.properties.getIssuer().getValue())
				.path("/oauth2/register/{id}").build(clientId.getValue());
		BearerAccessToken accessToken = new BearerAccessToken();
		OIDCClientInformation clientInformation = new OIDCClientInformation(clientId, Date.from(issueDate),
				clientMetadata, secret, registrationUri, accessToken);
		this.clientRepository.save(clientInformation);

		return clientInformation;
	}

	@Override
	@Transactional
	public OIDCClientInformation update(ClientID clientId, OIDCClientMetadata clientMetadata)
			throws InvalidClientException {
		OIDCClientInformation clientInformation = this.clientRepository.findByClientId(clientId);

		if (clientInformation == null) {
			throw InvalidClientException.BAD_ID;
		}

		clientMetadata.applyDefaults();
		Secret secret = null;

		if (!ClientAuthenticationMethod.NONE.equals(clientMetadata.getTokenEndpointAuthMethod())) {
			secret = this.properties.getRegistration().isUpdateSecret() ? new Secret() : clientInformation.getSecret();
		}

		BearerAccessToken accessToken = this.properties.getRegistration().isUpdateAccessToken()
				? new BearerAccessToken()
				: clientInformation.getRegistrationAccessToken();

		clientInformation = new OIDCClientInformation(clientId, clientInformation.getIDIssueDate(), clientMetadata,
				secret, clientInformation.getRegistrationURI(), accessToken);
		this.clientRepository.save(clientInformation);

		return clientInformation;
	}

}
