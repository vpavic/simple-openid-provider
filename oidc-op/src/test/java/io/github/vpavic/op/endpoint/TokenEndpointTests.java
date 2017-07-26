package io.github.vpavic.op.endpoint;

import java.net.URI;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
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

import io.github.vpavic.op.code.AuthorizationCodeContext;
import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.token.TokenService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest(controllers = TokenEndpoint.class, secure = false)
public class TokenEndpointTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@MockBean
	private AuthorizationCodeService authorizationCodeService;

	@MockBean
	private TokenService tokenService;

	@Test
	public void authCode_basicAuth_isOk() throws Exception {
		ClientID clientID = new ClientID("test-client");
		URI redirectionUri = URI.create("http://rp.example.com");
		AuthorizationCode authorizationCode = new AuthorizationCode();

		// @formatter:off
		AuthorizationRequest authRequest = new AuthorizationRequest.Builder(ResponseType.getDefault(), clientID)
				.redirectionURI(redirectionUri)
				.build();
		// @formatter:on

		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientID,
				new AuthorizationCodeGrant(authorizationCode, redirectionUri));

		AuthorizationCodeContext context = new AuthorizationCodeContext(authRequest,
				new TestingAuthenticationToken(new User("test", "n/a", AuthorityUtils.NO_AUTHORITIES), "n/a"));
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);

		MockHttpServletRequestBuilder request = post("/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).header("Authorization",
						new ClientSecretBasic(new ClientID("test"), new Secret("test")).toHTTPAuthorizationHeader());
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void authCode_postAuth_isOk() throws Exception {
		ClientID clientID = new ClientID("test-client");
		URI redirectionUri = URI.create("http://rp.example.com");
		AuthorizationCode authorizationCode = new AuthorizationCode();

		// @formatter:off
		AuthorizationRequest authRequest = new AuthorizationRequest.Builder(ResponseType.getDefault(), clientID)
				.redirectionURI(redirectionUri)
				.build();
		// @formatter:on

		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientID,
				new AuthorizationCodeGrant(authorizationCode, redirectionUri));

		AuthorizationCodeContext context = new AuthorizationCodeContext(authRequest,
				new TestingAuthenticationToken(new User("test", "n/a", AuthorityUtils.NO_AUTHORITIES), "n/a"));
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);

		MockHttpServletRequestBuilder request = post("/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void authCode_pkceDefault_isOk() throws Exception {
		ClientID clientID = new ClientID("test-client");
		URI redirectionUri = URI.create("http://rp.example.com");
		CodeVerifier codeVerifier = new CodeVerifier();
		AuthorizationCode authorizationCode = new AuthorizationCode();

		// @formatter:off
		AuthorizationRequest authRequest = new AuthorizationRequest.Builder(ResponseType.getDefault(), clientID)
				.redirectionURI(redirectionUri)
				.codeChallenge(codeVerifier, null)
				.build();
		// @formatter:on

		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientID,
				new AuthorizationCodeGrant(authorizationCode, redirectionUri, codeVerifier));

		AuthorizationCodeContext context = new AuthorizationCodeContext(authRequest,
				new TestingAuthenticationToken(new User("test", "n/a", AuthorityUtils.NO_AUTHORITIES), "n/a"));
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);

		MockHttpServletRequestBuilder request = post("/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void authCode_pkcePlain_isOk() throws Exception {
		ClientID clientID = new ClientID("test-client");
		URI redirectionUri = URI.create("http://rp.example.com");
		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.PLAIN;
		AuthorizationCode authorizationCode = new AuthorizationCode();

		// @formatter:off
		AuthorizationRequest authRequest = new AuthorizationRequest.Builder(ResponseType.getDefault(), clientID)
				.redirectionURI(redirectionUri)
				.codeChallenge(codeVerifier, codeChallengeMethod)
				.build();
		// @formatter:on

		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientID,
				new AuthorizationCodeGrant(authorizationCode, redirectionUri, codeVerifier));

		AuthorizationCodeContext context = new AuthorizationCodeContext(authRequest,
				new TestingAuthenticationToken(new User("test", "n/a", AuthorityUtils.NO_AUTHORITIES), "n/a"));
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);

		MockHttpServletRequestBuilder request = post("/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void authCode_pkceS256_isOk() throws Exception {
		ClientID clientID = new ClientID("test-client");
		URI redirectionUri = URI.create("http://rp.example.com");
		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
		AuthorizationCode authorizationCode = new AuthorizationCode();

		// @formatter:off
		AuthorizationRequest authRequest = new AuthorizationRequest.Builder(ResponseType.getDefault(), clientID)
				.redirectionURI(redirectionUri)
				.codeChallenge(codeVerifier, codeChallengeMethod)
				.build();
		// @formatter:on

		TokenRequest tokenRequest = new TokenRequest(URI.create("http://op.example.com"), clientID,
				new AuthorizationCodeGrant(authorizationCode, redirectionUri, codeVerifier));

		AuthorizationCodeContext context = new AuthorizationCodeContext(authRequest,
				new TestingAuthenticationToken(new User("test", "n/a", AuthorityUtils.NO_AUTHORITIES), "n/a"));
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(context);
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);

		MockHttpServletRequestBuilder request = post("/token").content(tokenRequest.toHTTPRequest().getQuery())
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void noParams_isBadRequest() throws Exception {
		this.mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED))
				.andExpect(status().isBadRequest());
	}

}
