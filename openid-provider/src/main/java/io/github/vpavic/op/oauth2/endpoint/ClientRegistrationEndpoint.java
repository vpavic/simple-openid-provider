package io.github.vpavic.op.oauth2.endpoint;

import java.net.URI;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.mvc.method.annotation.MvcUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.vpavic.op.config.OpenIdProviderProperties;
import io.github.vpavic.op.oauth2.client.ClientRepository;

@RestController
@RequestMapping(path = ClientRegistrationEndpoint.PATH_MAPPING)
@ConditionalOnProperty(prefix = "op.registration", name = "enabled", havingValue = "true")
public class ClientRegistrationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/register";

	private final String clientIdSuffix;

	private final ClientRepository clientRepository;

	public ClientRegistrationEndpoint(OpenIdProviderProperties properties, ClientRepository clientRepository) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");

		this.clientIdSuffix = UriComponentsBuilder.fromHttpUrl(properties.getIssuer()).build().getHost();
		this.clientRepository = clientRepository;
	}

	@PostMapping
	public ResponseEntity<String> handleRegistrationRequest(ServletWebRequest request) throws Exception {
		OIDCClientRegistrationRequest registrationRequest = resolveRegistrationRequest(request);

		String id = UUID.randomUUID().toString() + "." + this.clientIdSuffix;
		OIDCClientMetadata metadata = registrationRequest.getOIDCClientMetadata();
		metadata.applyDefaults();
		Secret secret = null;

		if (!ClientAuthenticationMethod.NONE.equals(metadata.getTokenEndpointAuthMethod())) {
			secret = new Secret();
		}

		URI registrationUri = MvcUriComponentsBuilder.fromController(ClientConfigurationEndpoint.class).build(id);
		OIDCClientInformation clientInformation = new OIDCClientInformation(new ClientID(id), new Date(), metadata,
				secret, registrationUri, new BearerAccessToken());

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
