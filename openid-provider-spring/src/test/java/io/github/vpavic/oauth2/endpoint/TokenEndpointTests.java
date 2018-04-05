package io.github.vpavic.oauth2.endpoint;

import java.net.URI;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AMR;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.grant.GrantHandler;
import io.github.vpavic.oauth2.grant.client.ClientCredentialsGrantHandler;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeContext;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeGrantHandler;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeService;
import io.github.vpavic.oauth2.grant.password.PasswordAuthenticationHandler;
import io.github.vpavic.oauth2.grant.password.ResourceOwnerPasswordCredentialsGrantHandler;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenContext;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenGrantHandler;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenStore;
import io.github.vpavic.oauth2.scope.ScopeResolver;
import io.github.vpavic.oauth2.token.AccessTokenRequest;
import io.github.vpavic.oauth2.token.IdTokenRequest;
import io.github.vpavic.oauth2.token.TokenService;

import static org.mockito.AdditionalAnswers.returnsSecondArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link TokenEndpoint}.
 */
@ExtendWith(SpringExtension.class)
@WebAppConfiguration
@ContextConfiguration
public class TokenEndpointTests {

	@Autowired
	private WebApplicationContext wac;

	private MockMvc mvc;

	@Autowired
	private ClientRepository clientRepository;

	@Autowired
	private AuthorizationCodeService authorizationCodeService;

	@Autowired
	private TokenService tokenService;

	@Autowired
	private ScopeResolver scopeResolver;

	@Autowired
	private PasswordAuthenticationHandler authenticationHandler;

	@Autowired
	private RefreshTokenStore refreshTokenStore;

	@BeforeEach
	public void setUp() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.wac).build();

		reset(this.clientRepository);
		reset(this.authorizationCodeService);
		reset(this.tokenService);
		reset(this.scopeResolver);
		reset(this.authenticationHandler);
		reset(this.refreshTokenStore);
	}

	@Test
	public void authCode_basicAuth_isOk() throws Exception {
		ClientID clientId = new ClientID("test-client");
		URI redirectUri = URI.create("http://rp.example.com");
		Scope scope = new Scope(OIDCScopeValue.OPENID);
		AuthorizationCode authorizationCode = new AuthorizationCode();

		ClientSecretBasic clientAuth = new ClientSecretBasic(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new AuthorizationCodeGrant(authorizationCode, redirectUri));

		AuthorizationCodeContext context = new AuthorizationCodeContext(new Subject("user"), clientId, redirectUri,
				scope, Instant.now(), new ACR("1"), Collections.singletonList(AMR.PWD), new SessionID("test"), null,
				null, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findById(any(ClientID.class)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
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
		ClientID clientId = new ClientID("test-client");
		URI redirectUri = URI.create("http://rp.example.com");
		AuthorizationCode authorizationCode = new AuthorizationCode();

		ClientSecretPost clientAuth = new ClientSecretPost(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new AuthorizationCodeGrant(authorizationCode, redirectUri));

		AuthorizationCodeContext context = new AuthorizationCodeContext(new Subject("user"), clientId, redirectUri,
				new Scope(OIDCScopeValue.OPENID), Instant.now(), new ACR("1"), Collections.singletonList(AMR.PWD),
				new SessionID("test"), null, null, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findById(any(ClientID.class)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_POST));
		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void authCode_mismatchedClientId_shouldThrowException() throws Exception {
		URI redirectUri = URI.create("http://rp.example.com");
		Scope scope = new Scope(OIDCScopeValue.OPENID);
		AuthorizationCode authorizationCode = new AuthorizationCode();

		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("bad-client"), new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new AuthorizationCodeGrant(authorizationCode, redirectUri));

		AuthorizationCodeContext context = new AuthorizationCodeContext(new Subject("user"),
				new ClientID("test-client"), redirectUri, scope, Instant.now(), new ACR("1"),
				Collections.singletonList(AMR.PWD), new SessionID("test"), null, null, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findById(any(ClientID.class)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.header("Authorization", clientAuth.toHTTPAuthorizationHeader());
		this.mvc.perform(request).andExpect(status().isBadRequest());
	}

	@Test
	public void authCode_mismatchedRedirectUri_shouldThrowException() throws Exception {
		ClientID clientId = new ClientID("test-client");
		Scope scope = new Scope(OIDCScopeValue.OPENID);
		AuthorizationCode authorizationCode = new AuthorizationCode();

		ClientSecretBasic clientAuth = new ClientSecretBasic(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new AuthorizationCodeGrant(authorizationCode, URI.create("http://bad.example.com")));

		AuthorizationCodeContext context = new AuthorizationCodeContext(new Subject("user"), clientId,
				URI.create("http://rp.example.com"), scope, Instant.now(), new ACR("1"),
				Collections.singletonList(AMR.PWD), new SessionID("test"), null, null, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findById(any(ClientID.class)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.header("Authorization", clientAuth.toHTTPAuthorizationHeader());
		this.mvc.perform(request).andExpect(status().isBadRequest());
	}

	@Test
	public void authCode_pkcePlain_isOk() throws Exception {
		ClientID clientId = new ClientID("test-client");
		URI redirectUri = URI.create("http://rp.example.com");
		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.PLAIN;
		AuthorizationCode authorizationCode = new AuthorizationCode();

		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientId,
				new AuthorizationCodeGrant(authorizationCode, redirectUri, codeVerifier));

		AuthorizationCodeContext context = new AuthorizationCodeContext(new Subject("user"), clientId, redirectUri,
				new Scope(OIDCScopeValue.OPENID), Instant.now(), new ACR("1"), Collections.singletonList(AMR.PWD),
				new SessionID("test"), CodeChallenge.compute(codeChallengeMethod, codeVerifier), codeChallengeMethod,
				null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findById(any(ClientID.class))).willReturn(client(ClientAuthenticationMethod.NONE));
		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.tokenService.createIdToken(any(IdTokenRequest.class))).willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void authCode_pkceS256_isOk() throws Exception {
		ClientID clientId = new ClientID("test-client");
		URI redirectUri = URI.create("http://rp.example.com");
		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
		AuthorizationCode authorizationCode = new AuthorizationCode();

		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientId,
				new AuthorizationCodeGrant(authorizationCode, URI.create("http://rp.example.com"), codeVerifier));

		AuthorizationCodeContext context = new AuthorizationCodeContext(new Subject("user"), clientId, redirectUri,
				new Scope(OIDCScopeValue.OPENID), Instant.now(), new ACR("1"), Collections.singletonList(AMR.PWD),
				new SessionID("test"), CodeChallenge.compute(codeChallengeMethod, codeVerifier), codeChallengeMethod,
				null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findById(any(ClientID.class))).willReturn(client(ClientAuthenticationMethod.NONE));
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
				new ResourceOwnerPasswordCredentialsGrant("user", new Secret("password")),
				new Scope(OIDCScopeValue.OPENID));

		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.clientRepository.findById(any(ClientID.class)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		given(this.authenticationHandler.authenticate(any(ResourceOwnerPasswordCredentialsGrant.class)))
				.willReturn(new Subject("user"));
		given(this.scopeResolver.resolve(any(Subject.class), any(Scope.class), any(OIDCClientMetadata.class)))
				.willAnswer(returnsSecondArg());
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
				new ResourceOwnerPasswordCredentialsGrant("user", new Secret("password")),
				new Scope(OIDCScopeValue.OPENID));

		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.clientRepository.findById(any(ClientID.class)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_POST));
		given(this.authenticationHandler.authenticate(any(ResourceOwnerPasswordCredentialsGrant.class)))
				.willReturn(new Subject("user"));
		given(this.scopeResolver.resolve(any(Subject.class), any(Scope.class), any(OIDCClientMetadata.class)))
				.willAnswer(returnsSecondArg());
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

		given(this.clientRepository.findById(any(ClientID.class)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		given(this.scopeResolver.resolve(any(Subject.class), any(Scope.class), any(OIDCClientMetadata.class)))
				.willAnswer(returnsSecondArg());
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

		given(this.clientRepository.findById(any(ClientID.class)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_POST));
		given(this.scopeResolver.resolve(any(Subject.class), any(Scope.class), any(OIDCClientMetadata.class)))
				.willAnswer(returnsSecondArg());
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void refreshToken_basicAuth_isOk() throws Exception {
		ClientID clientId = new ClientID("test-client");

		ClientSecretBasic clientAuth = new ClientSecretBasic(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new RefreshTokenGrant(new RefreshToken()));

		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.clientRepository.findById(any(ClientID.class)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.refreshTokenStore.load(any(RefreshToken.class))).willReturn(new RefreshTokenContext(
				new RefreshToken(), clientId, new Subject("user"), new Scope(OIDCScopeValue.OPENID), null));

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.header("Authorization", clientAuth.toHTTPAuthorizationHeader());
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void refreshToken_postAuth_isOk() throws Exception {
		ClientID clientId = new ClientID("test-client");

		ClientSecretPost clientAuth = new ClientSecretPost(clientId, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new RefreshTokenGrant(new RefreshToken()));

		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.clientRepository.findById(any(ClientID.class)))
				.willReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_POST));
		given(this.tokenService.createAccessToken(any(AccessTokenRequest.class))).willReturn(accessToken);
		given(this.refreshTokenStore.load(any(RefreshToken.class))).willReturn(new RefreshTokenContext(
				new RefreshToken(), clientId, new Subject("user"), new Scope(OIDCScopeValue.OPENID), null));

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void invalid_noParams_isBadRequest() throws Exception {
		this.mvc.perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED))
				.andExpect(status().isBadRequest());
	}

	private static OIDCClientInformation client(ClientAuthenticationMethod clientAuthenticationMethod) {
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.applyDefaults();
		clientMetadata.setRedirectionURI(URI.create("http://example.com"));
		clientMetadata.setScope(new Scope(OIDCScopeValue.OPENID));
		clientMetadata.setResponseTypes(Collections.singleton(new ResponseType(ResponseType.Value.CODE)));
		clientMetadata.setTokenEndpointAuthMethod(clientAuthenticationMethod);

		return new OIDCClientInformation(new ClientID("test-client"), new Date(), clientMetadata,
				ClientAuthenticationMethod.NONE.equals(clientAuthenticationMethod) ? null : new Secret("test-secret"));
	}

	@Configuration
	@EnableWebMvc
	static class Config {

		@Bean
		public ClientRepository clientRepository() {
			return mock(ClientRepository.class);
		}

		@Bean
		public AuthorizationCodeService authorizationCodeService() {
			return mock(AuthorizationCodeService.class);
		}

		@Bean
		public TokenService tokenService() {
			return mock(TokenService.class);
		}

		@Bean
		public ScopeResolver scopeResolver() {
			return mock(ScopeResolver.class);
		}

		@Bean
		public PasswordAuthenticationHandler authenticationHandler() {
			return mock(PasswordAuthenticationHandler.class);
		}

		@Bean
		public RefreshTokenStore refreshTokenStore() {
			return mock(RefreshTokenStore.class);
		}

		@Bean
		public TokenHandler tokenEndpointHandler() {
			AuthorizationCodeGrantHandler authorizationCodeGrantHandler = new AuthorizationCodeGrantHandler(
					clientRepository(), tokenService(), authorizationCodeService());
			ResourceOwnerPasswordCredentialsGrantHandler passwordCredentialsGrantHandler = new ResourceOwnerPasswordCredentialsGrantHandler(
					clientRepository(), tokenService(), scopeResolver(), authenticationHandler());
			ClientCredentialsGrantHandler clientCredentialsGrantHandler = new ClientCredentialsGrantHandler(
					clientRepository(), scopeResolver(), tokenService());
			RefreshTokenGrantHandler refreshTokenGrantHandler = new RefreshTokenGrantHandler(clientRepository(),
					tokenService(), refreshTokenStore());

			Map<Class<?>, GrantHandler> grantHandlers = new HashMap<>();
			grantHandlers.put(AuthorizationCodeGrant.class, authorizationCodeGrantHandler);
			grantHandlers.put(ResourceOwnerPasswordCredentialsGrant.class, passwordCredentialsGrantHandler);
			grantHandlers.put(ClientCredentialsGrant.class, clientCredentialsGrantHandler);
			grantHandlers.put(RefreshTokenGrant.class, refreshTokenGrantHandler);

			return new TokenHandler(grantHandlers, refreshTokenStore(), new Issuer("http://example.com"),
					clientRepository());
		}

		@Bean
		public TokenEndpoint tokenEndpoint() {
			return new TokenEndpoint(tokenEndpointHandler());
		}

	}

}
