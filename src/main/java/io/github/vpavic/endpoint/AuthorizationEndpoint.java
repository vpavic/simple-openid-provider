package io.github.vpavic.endpoint;

import java.net.URI;
import java.security.Principal;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.ConcurrentMap;

import javax.servlet.http.HttpServletRequest;

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
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

@Controller
@RequestMapping(path = "/authorize")
public class AuthorizationEndpoint {

	private static final String KID = "nimbus-oidc-provider";

	private final ConcurrentMap<String, Tokens> tokenStore;

	private final JWKSet jwkSet;

	public AuthorizationEndpoint(ConcurrentMap<String, Tokens> tokenStore,
			@Value("classpath:jwks.json") Resource jwkSetResource) throws Exception {
		this.tokenStore = Objects.requireNonNull(tokenStore);
		this.jwkSet = JWKSet.load(jwkSetResource.getFile());
	}

	@GetMapping
	public View handleAuthorizationRequest(HttpServletRequest request) throws Exception {
		AuthenticationRequest authRequest = AuthenticationRequest.parse(request.getQueryString());

		ClientID clientID = authRequest.getClientID();
		// TODO validate client

		URI redirectionURI = authRequest.getRedirectionURI();
		State state = authRequest.getState();

		Tokens tokens = createTokens(authRequest, request.getUserPrincipal());

		// Authorization Code Flow
		if (authRequest.getResponseType().impliesCodeFlow()) {
			AuthorizationCode code = new AuthorizationCode();
			State sessionState = State.parse(request.getSession().getId());
			ResponseMode responseMode = ResponseMode.QUERY;

			this.tokenStore.put(code.getValue(), tokens);

			AuthorizationResponse authResponse = new AuthenticationSuccessResponse(
					redirectionURI, code, null, null, state, sessionState, responseMode);

			return new RedirectView(authResponse.toURI().toString());
		}
		// TODO Implicit Flow
		else {
			throw new UnsupportedOperationException();
		}
	}

	private Tokens createTokens(AuthenticationRequest authRequest, Principal principal) throws Exception {
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
					.expirationTime(Date.from(LocalDateTime.now().plusMinutes(30).toInstant(ZoneOffset.UTC)))
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
