package io.github.vpavic.op.oauth2.endpoint;

import java.util.Objects;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientDeleteRequest;
import com.nimbusds.oauth2.sdk.client.ClientReadRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientUpdateRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import io.github.vpavic.op.config.OpenIdProviderProperties;
import io.github.vpavic.op.oauth2.client.ClientRepository;

@RestController
@RequestMapping(path = ClientConfigurationEndpoint.PATH_MAPPING)
@ConditionalOnProperty(prefix = "op.registration", name = "enabled", havingValue = "true")
public class ClientConfigurationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/register/{clientId:.*}";

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	public ClientConfigurationEndpoint(OpenIdProviderProperties properties, ClientRepository clientRepository) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");

		this.properties = properties;
		this.clientRepository = clientRepository;
	}

	@GetMapping
	public ResponseEntity<String> getClientConfiguration(@PathVariable String clientId, ServletWebRequest request)
			throws Exception {
		ClientReadRequest clientReadRequest = resolveReadRequest(request);

		AccessToken requestAccessToken = clientReadRequest.getAccessToken();

		OIDCClientInformation clientInformation = this.clientRepository.findByClientId(new ClientID(clientId));
		BearerAccessToken registrationAccessToken = clientInformation.getRegistrationAccessToken();

		if (registrationAccessToken == null || !requestAccessToken.equals(registrationAccessToken)) {
			throw new GeneralException(BearerTokenError.INVALID_TOKEN);
		}

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(clientInformation.toJSONObject().toJSONString());
		// @formatter:on
	}

	@PutMapping
	public ResponseEntity<String> updateClientConfiguration(@PathVariable String clientId, ServletWebRequest request)
			throws Exception {
		OIDCClientUpdateRequest clientUpdateRequest = resolveUpdateRequest(request);

		AccessToken requestAccessToken = clientUpdateRequest.getAccessToken();

		ClientID id = new ClientID(clientId);
		OIDCClientInformation clientInformation = this.clientRepository.findByClientId(id);
		BearerAccessToken registrationAccessToken = clientInformation.getRegistrationAccessToken();

		if (registrationAccessToken == null || !requestAccessToken.equals(registrationAccessToken)) {
			throw new GeneralException(BearerTokenError.INVALID_TOKEN);
		}

		OIDCClientMetadata metadata = clientUpdateRequest.getOIDCClientMetadata();
		metadata.applyDefaults();
		Secret secret = null;

		if (!ClientAuthenticationMethod.NONE.equals(metadata.getTokenEndpointAuthMethod())) {
			secret = this.properties.getRegistration().isUpdateSecret() ? new Secret() : clientInformation.getSecret();
		}

		BearerAccessToken accessToken = this.properties.getRegistration().isUpdateAccessToken()
				? new BearerAccessToken()
				: registrationAccessToken;

		clientInformation = new OIDCClientInformation(id, clientInformation.getIDIssueDate(), metadata, secret,
				clientInformation.getRegistrationURI(), accessToken);
		this.clientRepository.save(clientInformation);

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(clientInformation.toJSONObject().toJSONString());
		// @formatter:on
	}

	@DeleteMapping
	public ResponseEntity<Void> deleteClientConfiguration(@PathVariable String clientId, ServletWebRequest request)
			throws Exception {
		ClientDeleteRequest clientDeleteRequest = resolveDeleteRequest(request);

		AccessToken requestAccessToken = clientDeleteRequest.getAccessToken();

		ClientID id = new ClientID(clientId);
		OIDCClientInformation clientInformation = this.clientRepository.findByClientId(id);
		BearerAccessToken registrationAccessToken = clientInformation.getRegistrationAccessToken();

		if (registrationAccessToken == null || !requestAccessToken.equals(registrationAccessToken)) {
			throw new GeneralException(BearerTokenError.INVALID_TOKEN);
		}

		this.clientRepository.deleteByClientId(id);

		// @formatter:off
		return ResponseEntity.noContent()
				.build();
		// @formatter:on
	}

	@ExceptionHandler(GeneralException.class)
	public ResponseEntity<String> handleGeneralException(GeneralException e) {
		ErrorObject error = e.getErrorObject();

		// @formatter:off
		return ResponseEntity.status(error.getHTTPStatusCode())
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(error.toJSONObject().toJSONString());
		// @formatter:on
	}

	private ClientReadRequest resolveReadRequest(ServletWebRequest request) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request.getRequest());

		return ClientReadRequest.parse(httpRequest);
	}

	private OIDCClientUpdateRequest resolveUpdateRequest(ServletWebRequest request) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request.getRequest());

		return OIDCClientUpdateRequest.parse(httpRequest);
	}

	private ClientDeleteRequest resolveDeleteRequest(ServletWebRequest request) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request.getRequest());

		return ClientDeleteRequest.parse(httpRequest);
	}

}
