package io.github.vpavic.op.endpoint;

import java.net.URI;
import java.util.Objects;
import java.util.Set;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import io.github.vpavic.op.client.ClientRepository;
import io.github.vpavic.op.code.AuthorizationCodeContext;
import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.token.TokenService;

@Controller
@RequestMapping(path = "/authorize")
public class AuthorizationEndpoint {

	private final ClientRepository clientRepository;

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	public AuthorizationEndpoint(ClientRepository clientRepository, AuthorizationCodeService authorizationCodeService,
			TokenService tokenService) {
		this.clientRepository = Objects.requireNonNull(clientRepository);
		this.tokenService = Objects.requireNonNull(tokenService);
		this.authorizationCodeService = Objects.requireNonNull(authorizationCodeService);
	}

	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
	public String authorize(HTTPRequest request, Authentication authentication, HttpSession session) throws Exception {
		AuthorizationRequest authRequest = AuthorizationRequest.parse(request);

		try {
			authRequest = AuthenticationRequest.parse(request);
		}
		catch (ParseException e) {
			Scope scope = authRequest.getScope();

			if (scope != null && scope.contains(OIDCScopeValue.OPENID)) {
				throw e;
			}

			// otherwise still a valid OAuth2 request
		}

		OIDCClientInformation client = this.clientRepository.findByClientId(authRequest.getClientID());

		if (client == null) {
			throw new GeneralException(OAuth2Error.INVALID_CLIENT);
		}

		OIDCClientMetadata clientMetadata = client.getOIDCMetadata();

		URI redirectionURI = resolveRedirectionURI(authRequest, clientMetadata);
		Scope scope = resolveScope(authRequest, clientMetadata);

		ResponseType responseType = authRequest.getResponseType();

		if (!clientMetadata.getResponseTypes().contains(responseType)) {
			throw new GeneralException(OAuth2Error.INVALID_REQUEST);
		}

		UserDetails principal = (UserDetails) authentication.getPrincipal();
		State state = authRequest.getState();
		ResponseMode responseMode = authRequest.getResponseMode();

		AuthorizationResponse authResponse;

		// Authorization Code Flow
		if (responseType.impliesCodeFlow()) {
			AuthorizationCodeContext context = new AuthorizationCodeContext(authRequest, authentication);

			// OpenID Connect request
			if (authRequest instanceof AuthenticationRequest) {
				AuthorizationCode code = this.authorizationCodeService.create(context);
				State sessionState = State.parse(session.getId());

				authResponse = new AuthenticationSuccessResponse(redirectionURI, code, null, null, state, sessionState,
						responseMode);
			}
			// OAuth2 request
			else {
				AuthorizationCode code = this.authorizationCodeService.create(context);

				authResponse = new AuthorizationSuccessResponse(redirectionURI, code, null, state, responseMode);
			}
		}
		// Implicit Flow
		else if (!responseType.contains(ResponseType.Value.CODE)) {
			// OpenID Connect request
			if (authRequest instanceof AuthenticationRequest) {
				JWT idToken = this.tokenService.createIdToken((AuthenticationRequest) authRequest, principal);
				AccessToken accessToken = null;

				if (responseType.contains(ResponseType.Value.TOKEN)) {
					accessToken = this.tokenService.createAccessToken(authRequest, principal);
				}

				State sessionState = State.parse(session.getId());

				authResponse = new AuthenticationSuccessResponse(redirectionURI, null, idToken, accessToken, state,
						sessionState, responseMode);
			}
			// OAuth2 request
			else {
				AccessToken accessToken = this.tokenService.createAccessToken(authRequest, principal);

				authResponse = new AuthorizationSuccessResponse(redirectionURI, null, accessToken, state, responseMode);
			}
		}
		// Hybrid Flow
		else {
			// OpenID Connect request
			if (authRequest instanceof AuthenticationRequest) {
				JWT idToken = null;

				if (responseType.contains(OIDCResponseTypeValue.ID_TOKEN)) {
					idToken = this.tokenService.createIdToken((AuthenticationRequest) authRequest, principal);
				}

				AccessToken accessToken = null;

				if (responseType.contains(ResponseType.Value.TOKEN)) {
					accessToken = this.tokenService.createAccessToken(authRequest, principal);
				}

				AuthorizationCode code = this.authorizationCodeService
						.create(new AuthorizationCodeContext(authRequest, authentication));

				State sessionState = State.parse(session.getId());

				authResponse = new AuthenticationSuccessResponse(redirectionURI, code, idToken, accessToken, state,
						sessionState, responseMode);
			}
			// OAuth2 request
			else {
				AuthorizationCode code = this.authorizationCodeService
						.create(new AuthorizationCodeContext(authRequest, authentication));

				AccessToken accessToken = null;

				if (responseType.contains(ResponseType.Value.TOKEN)) {
					accessToken = this.tokenService.createAccessToken(authRequest, principal);
				}

				authResponse = new AuthorizationSuccessResponse(redirectionURI, code, accessToken, state, responseMode);
			}
		}

		return "redirect:" + authResponse.toURI();
	}

	private URI resolveRedirectionURI(AuthorizationRequest authRequest, OIDCClientMetadata clientMetadata)
			throws GeneralException {
		URI redirectionURI = authRequest.getRedirectionURI();
		Set<URI> registeredRedirectionURIs = clientMetadata.getRedirectionURIs();

		if (redirectionURI == null) {
			if (registeredRedirectionURIs.size() == 1) {
				redirectionURI = registeredRedirectionURIs.iterator().next();
			}
			else {
				throw new GeneralException(OAuth2Error.INVALID_REQUEST);
			}
		}
		else {
			if (!registeredRedirectionURIs.contains(redirectionURI)) {
				throw new GeneralException(OAuth2Error.INVALID_REQUEST);
			}
		}

		return redirectionURI;
	}

	private Scope resolveScope(AuthorizationRequest authRequest, OIDCClientMetadata clientMetadata)
			throws GeneralException {
		Scope scope = authRequest.getScope();
		Scope registeredScope = clientMetadata.getScope();

		if (scope == null) {
			scope = registeredScope;
		}
		else {
			if (registeredScope == null || !registeredScope.toStringList().containsAll(scope.toStringList())) {
				throw new GeneralException(OAuth2Error.INVALID_SCOPE);
			}
		}

		return scope;
	}

	@ExceptionHandler(GeneralException.class)
	public void handleParseException(GeneralException e, HttpServletResponse response) throws Exception {
		if (e.getClientID() == null || e.getRedirectionURI() == null) {
			response.sendError(HttpStatus.BAD_REQUEST.value(), e.getMessage());
		}
		else {
			AuthorizationResponse authResponse = new AuthenticationErrorResponse(e.getRedirectionURI(),
					e.getErrorObject(), e.getState(), e.getResponseMode());
			response.sendRedirect(authResponse.toURI().toString());
		}
	}

}
