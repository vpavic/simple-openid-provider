package io.github.vpavic.op.endpoint;

import java.net.URI;
import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import io.github.vpavic.op.code.AuthorizationCodeService;

@Controller
@RequestMapping(path = "/authorize")
public class AuthorizationEndpoint {

	private static final String KID = "nimbus-oidc-provider";

	private final AuthorizationCodeService authorizationCodeService;

	private final JWKSet jwkSet;

	public AuthorizationEndpoint(AuthorizationCodeService authorizationCodeService,
			@Value("classpath:jwks.json") Resource jwkSetResource) throws Exception {
		this.authorizationCodeService = Objects.requireNonNull(authorizationCodeService);
		this.jwkSet = JWKSet.load(jwkSetResource.getFile());
	}

	@RequestMapping(method = { RequestMethod.GET, RequestMethod.POST })
	public String handleAuthorizationRequest(HttpServletRequest request) throws Exception {
		Map<String, String> params = request.getParameterMap().entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue()[0]));
		AuthenticationRequest authRequest = AuthenticationRequest.parse(params);

		ClientID clientID = authRequest.getClientID();
		// TODO validate client

		URI redirectionURI = authRequest.getRedirectionURI();
		State state = authRequest.getState();

		Tokens tokens = createTokens(authRequest, request.getUserPrincipal());

		// Authorization Code Flow
		if (authRequest.getResponseType().impliesCodeFlow()) {
			AuthorizationCode code = this.authorizationCodeService.create(tokens);
			State sessionState = State.parse(request.getSession().getId());
			ResponseMode responseMode = ResponseMode.QUERY;

			AuthorizationResponse authResponse = new AuthenticationSuccessResponse(
					redirectionURI, code, null, null, state, sessionState, responseMode);

			return "redirect:" + authResponse.toURI();
		}
		// TODO Implicit Flow
		else {
			throw new UnsupportedOperationException();
		}
	}

	@ExceptionHandler(GeneralException.class)
	public String handleError(GeneralException e) {
		AuthenticationErrorResponse authResponse = new AuthenticationErrorResponse(
				e.getRedirectionURI(), e.getErrorObject(), e.getState(), e.getResponseMode());
		return "redirect:" + authResponse.toURI();
	}

	private Tokens createTokens(AuthenticationRequest authRequest, Principal principal)
			throws JOSEException {
		BearerAccessToken accessToken = new BearerAccessToken();
		RefreshToken refreshToken = new RefreshToken();

		if (authRequest.getScope().contains("openid")) {
			JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
					.keyID(KID)
					.build();
			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
					.issuer("https://self-issued.me")
					.subject(principal.getName())
					.audience(authRequest.getClientID().getValue())
					.expirationTime(Date.from(Instant.now().plus(30, ChronoUnit.MINUTES)))
					.issueTime(new Date())
					.build();
			SignedJWT idToken = new SignedJWT(header, claimsSet);
			JWSSigner signer = new RSASSASigner((RSAKey) this.jwkSet.getKeyByKeyId(KID));
			idToken.sign(signer);
			return new OIDCTokens(idToken, accessToken, refreshToken);
		}

		return new Tokens(accessToken, refreshToken);
	}

}
