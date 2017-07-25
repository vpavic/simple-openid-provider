package io.github.vpavic.op.endpoint;

import java.util.Map;
import java.util.Objects;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.token.TokenService;

@RestController
@RequestMapping(path = "/token")
public class TokenEndpoint {

	private final AuthorizationCodeService authorizationCodeService;

	private final TokenService tokenService;

	public TokenEndpoint(AuthorizationCodeService authorizationCodeService, TokenService tokenService) {
		this.authorizationCodeService = Objects.requireNonNull(authorizationCodeService);
		this.tokenService = Objects.requireNonNull(tokenService);
	}

	@PostMapping
	public JSONObject handleTokenRequest(HTTPRequest request) throws Exception {
		TokenRequest tokenRequest = TokenRequest.parse(request);

		ClientID clientID = tokenRequest.getClientID();
		// TODO validate client

		AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();

		// Authorization Code Grant Type
		if (authorizationGrant instanceof AuthorizationCodeGrant) {
			AuthorizationCodeGrant authorizationCodeGrant = (AuthorizationCodeGrant) authorizationGrant;
			Map<String, ?> authContext = this.authorizationCodeService
					.consume(authorizationCodeGrant.getAuthorizationCode());

			if (authContext == null) {
				throw new GeneralException(OAuth2Error.INVALID_REQUEST);
			}

			AuthorizationRequest authRequest = (AuthorizationRequest) authContext.get("authRequest");
			CodeChallenge codeChallenge = authRequest.getCodeChallenge();

			if (codeChallenge != null) {
				CodeChallengeMethod codeChallengeMethod = authRequest.getCodeChallengeMethod();

				if (codeChallengeMethod == null) {
					codeChallengeMethod = CodeChallengeMethod.PLAIN;
				}

				CodeVerifier codeVerifier = authorizationCodeGrant.getCodeVerifier();

				if (codeVerifier == null
						|| !codeChallenge.equals(CodeChallenge.compute(codeChallengeMethod, codeVerifier))) {
					throw new GeneralException(OAuth2Error.INVALID_REQUEST);
				}
			}

			Authentication authentication = (Authentication) authContext.get("authentication");
			UserDetails principal = (UserDetails) authentication.getPrincipal();

			AccessToken accessToken = this.tokenService.createAccessToken(authRequest, principal);
			RefreshToken refreshToken = this.tokenService.createRefreshToken(authRequest, principal);

			AccessTokenResponse tokenResponse;

			if (authRequest instanceof AuthenticationRequest) {
				JWT idToken = this.tokenService.createIdToken((AuthenticationRequest) authRequest, principal);
				OIDCTokens tokens = new OIDCTokens(idToken.serialize(), accessToken, refreshToken);

				tokenResponse = new OIDCTokenResponse(tokens);
			}
			else {
				Tokens tokens = new Tokens(accessToken, refreshToken);

				tokenResponse = new AccessTokenResponse(tokens);
			}

			return tokenResponse.toJSONObject();
		}

		return new TokenErrorResponse(OAuth2Error.UNSUPPORTED_GRANT_TYPE).toJSONObject();
	}

	@ExceptionHandler(ParseException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public JSONObject handleParseException(ParseException e) {
		ErrorObject error = e.getErrorObject();

		if (error == null) {
			error = OAuth2Error.INVALID_REQUEST.setDescription(e.getMessage());
		}

		return new TokenErrorResponse(error).toJSONObject();
	}

}
