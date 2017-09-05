package io.github.vpavic.op.client;

import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.oauth2.sdk.AbstractOptionallyIdentifiedRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.client.ClientType;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import org.springframework.stereotype.Component;

import io.github.vpavic.op.config.OpenIdProviderProperties;

@Component
public class ClientRequestValidator {

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	public ClientRequestValidator(OpenIdProviderProperties properties, ClientRepository clientRepository) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");

		this.properties = properties;
		this.clientRepository = clientRepository;
	}

	public void validateRequest(AbstractOptionallyIdentifiedRequest request) throws Exception {
		ClientAuthentication clientAuthentication = request.getClientAuthentication();

		OIDCClientInformation client = this.clientRepository.findByClientId(
				(clientAuthentication != null) ? clientAuthentication.getClientID() : request.getClientID());

		if (client == null) {
			throw InvalidClientException.BAD_ID;
		}

		if (client.inferClientType() == ClientType.CONFIDENTIAL) {
			if (clientAuthentication == null) {
				throw InvalidClientException.BAD_SECRET;
			}

			ClientAuthenticationVerifier<OIDCClientInformation> verifier = new ClientAuthenticationVerifier<>(
					new ClientInformationCredentialsSelector(), null,
					Collections.singleton(new Audience(this.properties.getIssuer())));

			Context<OIDCClientInformation> context = new Context<>();
			context.set(client);
			verifier.verify(clientAuthentication, null, context);
		}
	}

	private static class ClientInformationCredentialsSelector
			implements ClientCredentialsSelector<OIDCClientInformation> {

		@Override
		public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod,
				Context<OIDCClientInformation> context) throws InvalidClientException {
			OIDCClientInformation client = context.get();
			ClientAuthenticationMethod configuredAuthMethod = client.getOIDCMetadata().getTokenEndpointAuthMethod();

			if (configuredAuthMethod != null && !configuredAuthMethod.equals(authMethod)) {
				throw InvalidClientException.NOT_REGISTERED_FOR_AUTH_METHOD;
			}

			return Collections.singletonList(client.getSecret());
		}

		@Override
		public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID,
				ClientAuthenticationMethod authMethod, JWSHeader jwsHeader, boolean forceRefresh,
				Context<OIDCClientInformation> context) throws InvalidClientException {
			return Collections.emptyList();
		}

	}

}
