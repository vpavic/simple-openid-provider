package io.github.vpavic.op.endpoint;

import java.net.URI;
import java.util.Date;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import io.github.vpavic.op.client.ClientRepository;
import io.github.vpavic.op.code.AuthorizationCodeContext;
import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.token.TokenService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
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
	private ClientRepository clientRepository;

	@MockBean
	private ClientAuthenticationVerifier<ClientRepository> clientAuthenticationVerifier;

	@MockBean
	private AuthorizationCodeService authorizationCodeService;

	@MockBean
	private TokenService tokenService;

	@Test
	public void authCode_basicAuth_isOk() throws Exception {
		ClientID clientID = new ClientID("test-client");
		URI redirectionUri = URI.create("http://rp.example.com");
		Scope scope = new Scope(OIDCScopeValue.OPENID);
		AuthorizationCode authorizationCode = new AuthorizationCode();

		ClientSecretBasic clientAuth = new ClientSecretBasic(clientID, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new AuthorizationCodeGrant(authorizationCode, redirectionUri));

		AuthorizationCodeContext context = new AuthorizationCodeContext(
				new TestingAuthenticationToken(new User("test-secret", "n/a", AuthorityUtils.NO_AUTHORITIES), "n/a"),
				clientID, scope, null, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(UserDetails.class), any(ClientID.class), any(Scope.class)))
				.willReturn(accessToken);
		given(this.tokenService.createIdToken(any(UserDetails.class), any(ClientID.class), any(Scope.class), isNull()))
				.willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.header("Authorization", clientAuth.toHTTPAuthorizationHeader());
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void authCode_postAuth_isOk() throws Exception {
		ClientID clientID = new ClientID("test-client");
		URI redirectionUri = URI.create("http://rp.example.com");
		Scope scope = new Scope(OIDCScopeValue.OPENID);
		AuthorizationCode authorizationCode = new AuthorizationCode();

		ClientSecretPost clientAuth = new ClientSecretPost(clientID, new Secret("test-secret"));
		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientAuth,
				new AuthorizationCodeGrant(authorizationCode, redirectionUri));

		AuthorizationCodeContext context = new AuthorizationCodeContext(
				new TestingAuthenticationToken(new User("test", "n/a", AuthorityUtils.NO_AUTHORITIES), "n/a"), clientID,
				scope, null, null);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(UserDetails.class), any(ClientID.class), any(Scope.class)))
				.willReturn(accessToken);
		given(this.tokenService.createIdToken(any(UserDetails.class), any(ClientID.class), any(Scope.class), isNull()))
				.willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void authCode_pkcePlain_isOk() throws Exception {
		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(testClient(ClientAuthenticationMethod.NONE));

		ClientID clientID = new ClientID("test-client");
		URI redirectionUri = URI.create("http://rp.example.com");
		Scope scope = new Scope(OIDCScopeValue.OPENID);
		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.PLAIN;
		CodeChallenge codeChallenge = CodeChallenge.compute(codeChallengeMethod, codeVerifier);
		AuthorizationCode authorizationCode = new AuthorizationCode();

		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientID,
				new AuthorizationCodeGrant(authorizationCode, redirectionUri, codeVerifier));

		AuthorizationCodeContext context = new AuthorizationCodeContext(
				new TestingAuthenticationToken(new User("test", "n/a", AuthorityUtils.NO_AUTHORITIES), "n/a"), clientID,
				scope, codeChallenge, codeChallengeMethod);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(UserDetails.class), any(ClientID.class), any(Scope.class)))
				.willReturn(accessToken);
		given(this.tokenService.createIdToken(any(UserDetails.class), any(ClientID.class), any(Scope.class), isNull()))
				.willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void authCode_pkceS256_isOk() throws Exception {
		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(testClient(ClientAuthenticationMethod.NONE));

		ClientID clientID = new ClientID("test-client");
		URI redirectionUri = URI.create("http://rp.example.com");
		Scope scope = new Scope(OIDCScopeValue.OPENID);
		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
		CodeChallenge codeChallenge = CodeChallenge.compute(codeChallengeMethod, codeVerifier);
		AuthorizationCode authorizationCode = new AuthorizationCode();

		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientID,
				new AuthorizationCodeGrant(authorizationCode, redirectionUri, codeVerifier));

		AuthorizationCodeContext context = new AuthorizationCodeContext(
				new TestingAuthenticationToken(new User("test", "n/a", AuthorityUtils.NO_AUTHORITIES), "n/a"), clientID,
				scope, codeChallenge, codeChallengeMethod);
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(UserDetails.class), any(ClientID.class), any(Scope.class)))
				.willReturn(accessToken);
		given(this.tokenService.createIdToken(any(UserDetails.class), any(ClientID.class), any(Scope.class), isNull()))
				.willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/oauth2/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void noParams_isBadRequest() throws Exception {
		this.mvc.perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED))
				.andExpect(status().isBadRequest());
	}

	private static OIDCClientInformation testClient(ClientAuthenticationMethod authMethod) {
		ClientID clientID = new ClientID("test-client");
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.applyDefaults();
		clientMetadata.setRedirectionURI(URI.create("http://example.com"));
		clientMetadata.setTokenEndpointAuthMethod(authMethod);
		Secret secret = new Secret("test-secret");

		return new OIDCClientInformation(clientID, new Date(), clientMetadata, secret);
	}

}
