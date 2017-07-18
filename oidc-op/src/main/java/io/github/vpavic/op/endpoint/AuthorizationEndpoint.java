package io.github.vpavic.op.endpoint;

import java.net.URI;
import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
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
	public void authorize(HttpServletRequest request, HttpServletResponse response) throws Exception {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
		HTTPResponse httpResponse;

		try {
			AuthenticationRequest authRequest = AuthenticationRequest.parse(httpRequest);

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

				httpResponse = new AuthenticationSuccessResponse(redirectionURI, code, null, null, state, sessionState,
						responseMode).toHTTPResponse();
			}
			// TODO Implicit Flow
			else {
				throw new UnsupportedOperationException();
			}
		}
		catch (ParseException e) {
			if (e.getClientID() == null || e.getRedirectionURI() == null) {
				httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);
			}
			else {
				httpResponse = new AuthenticationErrorResponse(e.getRedirectionURI(), e.getErrorObject(), e.getState(),
						e.getResponseMode()).toHTTPResponse();
			}
		}

		ServletUtils.applyHTTPResponse(httpResponse, response);
	}

	private Tokens createTokens(AuthenticationRequest authRequest, Principal principal) throws JOSEException {
		BearerAccessToken accessToken = new BearerAccessToken();
		RefreshToken refreshToken = new RefreshToken();

		if (authRequest.getScope().contains("openid")) {
			JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build();
			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().issuer("https://self-issued.me")
					.subject(principal.getName()).audience(authRequest.getClientID().getValue())
					.expirationTime(Date.from(Instant.now().plus(30, ChronoUnit.MINUTES))).issueTime(new Date())
					.build();
			SignedJWT idToken = new SignedJWT(header, claimsSet);
			JWSSigner signer = new RSASSASigner((RSAKey) this.jwkSet.getKeyByKeyId(KID));
			idToken.sign(signer);
			return new OIDCTokens(idToken, accessToken, refreshToken);
		}

		return new Tokens(accessToken, refreshToken);
	}

}
