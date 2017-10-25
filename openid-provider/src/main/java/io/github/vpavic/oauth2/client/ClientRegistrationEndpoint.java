package io.github.vpavic.oauth2.client;

import java.util.List;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
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
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientUpdateRequest;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.ServletWebRequest;

import io.github.vpavic.oauth2.OpenIdProviderProperties;

@Controller
@RequestMapping(path = ClientRegistrationEndpoint.PATH_MAPPING)
public class ClientRegistrationEndpoint {

	public static final String PATH_MAPPING = "/oauth2/register";

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	private final ClientService clientService;

	public ClientRegistrationEndpoint(OpenIdProviderProperties properties, ClientRepository clientRepository,
			ClientService clientService) {
		Objects.requireNonNull(properties, "properties must not be null");
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(clientService, "clientService must not be null");

		this.properties = properties;
		this.clientRepository = clientRepository;
		this.clientService = clientService;
	}

	@GetMapping
	public ResponseEntity<String> getClientRegistrations(ServletWebRequest request) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request.getRequest());
		String authorizationHeader = httpRequest.getAuthorization();

		if (authorizationHeader == null) {
			throw new GeneralException(BearerTokenError.INVALID_TOKEN);
		}

		BearerAccessToken requestAccessToken = BearerAccessToken.parse(authorizationHeader);
		validateAccessToken(requestAccessToken);
		List<OIDCClientInformation> clients = this.clientRepository.findAll();

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(toJsonObject(clients).toJSONString());
		// @formatter:on
	}

	@PostMapping
	public ResponseEntity<String> handleClientRegistrationRequest(ServletWebRequest request) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request.getRequest());
		OIDCClientRegistrationRequest registrationRequest = OIDCClientRegistrationRequest.parse(httpRequest);

		if (!this.properties.getRegistration().isOpenRegistrationEnabled()) {
			validateAccessToken(registrationRequest.getAccessToken());
		}

		OIDCClientMetadata clientMetadata = registrationRequest.getOIDCClientMetadata();
		OIDCClientInformation client = this.clientService.create(clientMetadata);

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(client.toJSONObject().toJSONString());
		// @formatter:on
	}

	@GetMapping(path = "/{id:.*}")
	public ResponseEntity<String> getClientConfiguration(@PathVariable String id, ServletWebRequest request)
			throws Exception {
		ClientReadRequest clientReadRequest = resolveReadRequest(request);

		OIDCClientInformation client = resolveAndValidateClient(new ClientID(id), clientReadRequest);

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(client.toJSONObject().toJSONString());
		// @formatter:on
	}

	@PutMapping(path = "/{id:.*}")
	public ResponseEntity<String> updateClientConfiguration(@PathVariable String id, ServletWebRequest request)
			throws Exception {
		OIDCClientUpdateRequest clientUpdateRequest = resolveUpdateRequest(request);

		ClientID clientId = new ClientID(id);
		resolveAndValidateClient(clientId, clientUpdateRequest);

		OIDCClientMetadata clientMetadata = clientUpdateRequest.getOIDCClientMetadata();
		OIDCClientInformation client = this.clientService.update(clientId, clientMetadata);

		// @formatter:off
		return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON_UTF8)
				.body(client.toJSONObject().toJSONString());
		// @formatter:on
	}

	@DeleteMapping(path = "/{id:.*}")
	public ResponseEntity<Void> deleteClientConfiguration(@PathVariable String id, ServletWebRequest request)
			throws Exception {
		ClientDeleteRequest clientDeleteRequest = resolveDeleteRequest(request);

		ClientID clientId = new ClientID(id);
		resolveAndValidateClient(clientId, clientDeleteRequest);

		this.clientRepository.deleteById(clientId);

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

	private void validateAccessToken(AccessToken requestAccessToken) throws GeneralException {
		BearerAccessToken apiAccessToken = this.properties.getRegistration().getApiAccessToken();

		if (requestAccessToken == null || !requestAccessToken.equals(apiAccessToken)) {
			throw new GeneralException(BearerTokenError.INVALID_TOKEN);
		}
	}

	private JSONObject toJsonObject(List<OIDCClientInformation> clients) {
		JSONObject object = new JSONObject();
		JSONArray clientList = new JSONArray();
		clients.forEach(client -> clientList.add(client.toJSONObject()));
		object.put("clients", clientList);

		return object;
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

	private OIDCClientInformation resolveAndValidateClient(ClientID clientId, ProtectedResourceRequest request)
			throws GeneralException {
		OIDCClientInformation client = this.clientRepository.findById(clientId);

		if (client != null) {
			AccessToken requestAccessToken = request.getAccessToken();
			BearerAccessToken registrationAccessToken = client.getRegistrationAccessToken();
			BearerAccessToken apiAccessToken = this.properties.getRegistration().getApiAccessToken();

			if (requestAccessToken.equals(registrationAccessToken) || requestAccessToken.equals(apiAccessToken)) {
				return client;
			}
		}

		throw new GeneralException(BearerTokenError.INVALID_TOKEN);
	}

}
