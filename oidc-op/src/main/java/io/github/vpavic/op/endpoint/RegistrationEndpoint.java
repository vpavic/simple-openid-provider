package io.github.vpavic.op.endpoint;

import java.util.Date;
import java.util.Objects;
import java.util.UUID;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.vpavic.op.client.ClientRepository;
import io.github.vpavic.op.config.OpenIdProviderProperties;

@RestController
@RequestMapping(path = RegistrationEndpoint.PATH_MAPPING)
public class RegistrationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/register";

	private final String clientIdSuffix;

	private final ClientRepository clientRepository;

	public RegistrationEndpoint(OpenIdProviderProperties properties, ClientRepository clientRepository) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");

		// @formatter:off
		this.clientIdSuffix = UriComponentsBuilder.fromHttpUrl(properties.getIssuer())
				.build()
				.getHost();
		// @formatter:on

		this.clientRepository = clientRepository;
	}

	@PostMapping
	public ResponseEntity<String> handleRegistrationRequest(ServletWebRequest request) throws Exception {
		OIDCClientRegistrationRequest registrationRequest = resolveRegistrationRequest(request);
		OIDCClientMetadata clientMetadata = registrationRequest.getOIDCClientMetadata();
		ClientID clientID = new ClientID(UUID.randomUUID().toString() + "." + this.clientIdSuffix);
		OIDCClientInformation clientInformation = new OIDCClientInformation(clientID, new Date(), clientMetadata,
				new Secret());

		this.clientRepository.save(clientInformation);

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(clientInformation.toJSONObject().toJSONString());
		// @formatter:on
	}

	private OIDCClientRegistrationRequest resolveRegistrationRequest(ServletWebRequest request) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request.getRequest());

		return OIDCClientRegistrationRequest.parse(httpRequest);
	}

}
