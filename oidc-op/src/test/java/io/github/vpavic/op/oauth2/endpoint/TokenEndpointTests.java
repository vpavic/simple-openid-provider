package io.github.vpavic.op.oauth2.endpoint;

import java.net.URI;
import java.time.Instant;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import io.github.vpavic.op.oauth2.client.ClientRequestValidator;
import io.github.vpavic.op.oauth2.code.AuthorizationCodeContext;
import io.github.vpavic.op.oauth2.code.AuthorizationCodeService;
import io.github.vpavic.op.oauth2.token.AccessTokenRequest;
import io.github.vpavic.op.oauth2.token.ClaimsMapper;
import io.github.vpavic.op.oauth2.token.IdTokenRequest;
import io.github.vpavic.op.oauth2.token.RefreshTokenContext;
import io.github.vpavic.op.oauth2.token.RefreshTokenStore;
import io.github.vpavic.op.oauth2.token.TokenService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link TokenEndpoint}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebMvcTest(controllers = TokenEndpoint.class, secure = false)
public class TokenEndpointTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@MockBean
	private ClientRequestValidator clientRequestValidator;

	@MockBean
	private AuthorizationCodeService authorizationCodeService;

	@MockBean
	private TokenService tokenService;

	@MockBean
	private AuthenticationManager authenticationManager;

	@MockBean
	private RefreshTokenStore refreshTokenStore;

	@MockBean
	private ClaimsMapper claimsMapper;

	@Test
	public void authCode_basicAuth_isOk() throws Exception {
		ClientID clientID = new ClientID("test-client");
		URI redirectionUri = URI.create("http://rp.example.com");
		Scope scope = new Scope(OIDCScopeValue.OPENID);
		AuthorizationCode authorizationCode = new AuthorizationCode();

		ClientSecretBasic clientAuth = new ClientSecretBasic(clientID, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new AuthorizationCodeGrant(authorizationCode, redirectionUri));

		AuthorizationCodeContext context = new AuthorizationCodeContext("user", clientID, scope, Instant.now(),
				new ACR("1"), AMR.PWD, "test", null, null, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.header("Authorization", clientAuth.toHTTPAuthorizationHeader());
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void authCode_postAuth_isOk() throws Exception {
		ClientID clientID = new ClientID("test-client");
		AuthorizationCode authorizationCode = new AuthorizationCode();

		ClientSecretPost clientAuth = new ClientSecretPost(clientID, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new AuthorizationCodeGrant(authorizationCode, URI.create("http://rp.example.com")));

		AuthorizationCodeContext context = new AuthorizationCodeContext("user", clientID,
				new Scope(OIDCScopeValue.OPENID), Instant.now(), new ACR("1"), AMR.PWD, "test", null, null, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void authCode_pkcePlain_isOk() throws Exception {
		ClientID clientID = new ClientID("test-client");
		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.PLAIN;
		AuthorizationCode authorizationCode = new AuthorizationCode();

		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientID,
				new AuthorizationCodeGrant(authorizationCode, URI.create("http://rp.example.com"), codeVerifier));

		AuthorizationCodeContext context = new AuthorizationCodeContext("user", clientID,
				new Scope(OIDCScopeValue.OPENID), Instant.now(), new ACR("1"), AMR.PWD, "test",
				CodeChallenge.compute(codeChallengeMethod, codeVerifier), codeChallengeMethod, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void authCode_pkceS256_isOk() throws Exception {
		ClientID clientID = new ClientID("test-client");
		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
		AuthorizationCode authorizationCode = new AuthorizationCode();

		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientID,
				new AuthorizationCodeGrant(authorizationCode, URI.create("http://rp.example.com"), codeVerifier));

		AuthorizationCodeContext context = new AuthorizationCodeContext("user", clientID,
				new Scope(OIDCScopeValue.OPENID), Instant.now(), new ACR("1"), AMR.PWD, "test",
				CodeChallenge.compute(codeChallengeMethod, codeVerifier), codeChallengeMethod, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void resourceOwnerPasswordCredentials_basicAuth_isOk() throws Exception {
		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("test-client"), new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new ResourceOwnerPasswordCredentialsGrant("user", new Secret("password")), new Scope("test"));

		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(
				new TestingAuthenticationToken(new User("user", "n/a", AuthorityUtils.NO_AUTHORITIES), "n/a"));
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.header("Authorization", clientAuth.toHTTPAuthorizationHeader());
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void resourceOwnerPasswordCredentials_postAuth_isOk() throws Exception {
		ClientSecretPost clientAuth = new ClientSecretPost(new ClientID("test-client"), new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new ResourceOwnerPasswordCredentialsGrant("user", new Secret("password")), new Scope("test"));

		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(
				new TestingAuthenticationToken(new User("user", "n/a", AuthorityUtils.NO_AUTHORITIES), "n/a"));
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void clientCredentials_basicAuth_isOk() throws Exception {
		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("test-client"), new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new ClientCredentialsGrant(), new Scope("test"));

		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.header("Authorization", clientAuth.toHTTPAuthorizationHeader());
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void clientCredentials_postAuth_isOk() throws Exception {
		ClientSecretPost clientAuth = new ClientSecretPost(new ClientID("test-client"), new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new ClientCredentialsGrant(), new Scope("test"));

		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void refreshToken_basicAuth_isOk() throws Exception {
		ClientID clientID = new ClientID("test-client");

		ClientSecretBasic clientAuth = new ClientSecretBasic(clientID, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new RefreshTokenGrant(new RefreshToken()));

		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.refreshTokenStore.load(any(RefreshToken.class)))
				.willReturn(new RefreshTokenContext("user", clientID, new Scope(OIDCScopeValue.OPENID), null));

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.header("Authorization", clientAuth.toHTTPAuthorizationHeader());
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void refreshToken_postAuth_isOk() throws Exception {
		ClientID clientID = new ClientID("test-client");

		ClientSecretPost clientAuth = new ClientSecretPost(clientID, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new RefreshTokenGrant(new RefreshToken()));

		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.refreshTokenStore.load(any(RefreshToken.class)))
				.willReturn(new RefreshTokenContext("user", clientID, new Scope(OIDCScopeValue.OPENID), null));

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void invalid_noParams_isBadRequest() throws Exception {
		this.mvc.perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED))
				.andExpect(status().isBadRequest());
	}

}
