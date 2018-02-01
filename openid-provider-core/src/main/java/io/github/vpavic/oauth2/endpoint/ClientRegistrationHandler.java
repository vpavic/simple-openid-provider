package io.github.vpavic.oauth2.endpoint;

import java.util.List;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import com.nimbusds.oauth2.sdk.client.ClientDeleteRequest;
import com.nimbusds.oauth2.sdk.client.ClientReadRequest;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientUpdateRequest;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.client.ClientService;

public class ClientRegistrationHandler {

	private final ClientRepository clientRepository;

	private final ClientService clientService;

	private boolean allowOpenRegistration;

	private BearerAccessToken apiAccessToken;

	public ClientRegistrationHandler(ClientRepository clientRepository, ClientService clientService) {
		Objects.requireNonNull(clientRepository, "clientRepository must not be null");
		Objects.requireNonNull(clientService, "clientService must not be null");
		this.clientRepository = clientRepository;
		this.clientService = clientService;
	}

	public void setAllowOpenRegistration(boolean allowOpenRegistration) {
		this.allowOpenRegistration = allowOpenRegistration;
	}

	public void setApiAccessToken(BearerAccessToken apiAccessToken) {
		this.apiAccessToken = apiAccessToken;
	}

	public HTTPResponse getClientRegistrations(HTTPRequest httpRequest) {
		HTTPResponse httpResponse;

		try {
			String authorizationHeader = httpRequest.getAuthorization();

			if (authorizationHeader == null) {
				throw new GeneralException(BearerTokenError.INVALID_TOKEN);
			}

			BearerAccessToken requestAccessToken = BearerAccessToken.parse(authorizationHeader);
			validateAccessToken(requestAccessToken);
			List<OIDCClientInformation> clients = this.clientRepository.findAll();

			httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
			httpResponse.setContentType("application/json; charset=UTF-8");
			httpResponse.setContent(toJsonObject(clients).toJSONString());
		}
		catch (GeneralException e) {
			ClientRegistrationResponse registrationResponse = new ClientRegistrationErrorResponse(e.getErrorObject());
			httpResponse = registrationResponse.toHTTPResponse();
		}

		return httpResponse;
	}

	public HTTPResponse handleClientRegistrationRequest(HTTPRequest httpRequest) {
		HTTPResponse httpResponse;

		try {
			OIDCClientRegistrationRequest registrationRequest = OIDCClientRegistrationRequest.parse(httpRequest);

			if (!this.allowOpenRegistration) {
				validateAccessToken(registrationRequest.getAccessToken());
			}

			OIDCClientMetadata clientMetadata = registrationRequest.getOIDCClientMetadata();
			OIDCClientInformation clientInformation = this.clientService.create(clientMetadata, true);

			OIDCClientInformationResponse registrationResponse = new OIDCClientInformationResponse(clientInformation);
			httpResponse = registrationResponse.toHTTPResponse();
		}
		catch (GeneralException e) {
			ClientRegistrationErrorResponse registrationResponse = new ClientRegistrationErrorResponse(
					e.getErrorObject());
			httpResponse = registrationResponse.toHTTPResponse();
		}

		return httpResponse;
	}

	public HTTPResponse getClientConfiguration(HTTPRequest httpRequest, ClientID id) {
		HTTPResponse httpResponse;

		try {
			ClientReadRequest clientReadRequest = ClientReadRequest.parse(httpRequest);
			OIDCClientInformation client = resolveAndValidateClient(id, clientReadRequest);
			OIDCClientInformationResponse registrationResponse = new OIDCClientInformationResponse(client);
			httpResponse = registrationResponse.toHTTPResponse();
		}
		catch (GeneralException e) {
			ClientRegistrationErrorResponse registrationResponse = new ClientRegistrationErrorResponse(
					e.getErrorObject());
			httpResponse = registrationResponse.toHTTPResponse();
		}

		return httpResponse;
	}

	public HTTPResponse updateClientConfiguration(HTTPRequest httpRequest, ClientID id) {
		HTTPResponse httpResponse;

		try {
			OIDCClientUpdateRequest clientUpdateRequest = OIDCClientUpdateRequest.parse(httpRequest);
			resolveAndValidateClient(id, clientUpdateRequest);

			OIDCClientMetadata clientMetadata = clientUpdateRequest.getOIDCClientMetadata();
			OIDCClientInformation client = this.clientService.update(id, clientMetadata);

			OIDCClientInformationResponse registrationResponse = new OIDCClientInformationResponse(client);
			httpResponse = registrationResponse.toHTTPResponse();
		}
		catch (GeneralException e) {
			ClientRegistrationErrorResponse registrationResponse = new ClientRegistrationErrorResponse(
					e.getErrorObject());
			httpResponse = registrationResponse.toHTTPResponse();
		}

		return httpResponse;
	}

	public HTTPResponse deleteClientConfiguration(HTTPRequest httpRequest, ClientID id) {
		HTTPResponse httpResponse;

		try {
			ClientDeleteRequest clientDeleteRequest = ClientDeleteRequest.parse(httpRequest);
			resolveAndValidateClient(id, clientDeleteRequest);

			this.clientRepository.deleteById(id);

			httpResponse = new HTTPResponse(204);
		}
		catch (GeneralException e) {
			ClientRegistrationResponse registrationResponse = new ClientRegistrationErrorResponse(e.getErrorObject());
			httpResponse = registrationResponse.toHTTPResponse();
		}

		return httpResponse;
	}

	private void validateAccessToken(AccessToken requestAccessToken) throws GeneralException {
		BearerAccessToken apiAccessToken = this.apiAccessToken;

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

	private OIDCClientInformation resolveAndValidateClient(ClientID clientId, ProtectedResourceRequest request)
			throws GeneralException {
		OIDCClientInformation client = this.clientRepository.findById(clientId);

		if (client != null) {
			AccessToken requestAccessToken = request.getAccessToken();
			BearerAccessToken registrationAccessToken = client.getRegistrationAccessToken();
			BearerAccessToken apiAccessToken = this.apiAccessToken;

			if (requestAccessToken.equals(registrationAccessToken) || requestAccessToken.equals(apiAccessToken)) {
				return client;
			}
		}

		throw new GeneralException(BearerTokenError.INVALID_TOKEN);
	}

}
