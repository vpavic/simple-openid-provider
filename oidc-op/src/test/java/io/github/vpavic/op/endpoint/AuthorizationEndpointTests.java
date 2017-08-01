package io.github.vpavic.op.endpoint;

import java.net.URI;
import java.util.Collections;
import java.util.Date;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import io.github.vpavic.op.client.ClientRepository;
import io.github.vpavic.op.code.AuthorizationCodeContext;
import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.token.TokenService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest(AuthorizationEndpoint.class)
public class AuthorizationEndpointTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@MockBean
	private ClientRepository clientRepository;

	@MockBean
	private AuthorizationCodeService authorizationCodeService;

	@MockBean
	private TokenService tokenService;

	private MockHttpSession session;

	@Before
	public void setUp() {
		this.session = new MockHttpSession();
	}

	// OAuth2 requests

	@Test
	@WithMockUser
	public void oAuth2_authCode_get_minimumParams_isOk() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(testClient(new ResponseType(ResponseType.Value.CODE)));
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new BearerAccessToken());
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get("/authorize?response_type=code&client_id=test-client")
				.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}", authorizationCode.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_authCode_post_minimumParams_isOk() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(testClient(new ResponseType(ResponseType.Value.CODE)));
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new BearerAccessToken());
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = post("/authorize").content("response_type=code&client_id=test-client")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}", authorizationCode.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_implicit_get_minimumParams_isOk() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(testClient(new ResponseType(ResponseType.Value.TOKEN)));
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());

		MockHttpServletRequestBuilder request = get("/authorize?response_type=token&client_id=test-client")
				.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&token_type=Bearer", accessToken.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_implicit_post_minimumParams_isOk() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(testClient(new ResponseType(ResponseType.Value.TOKEN)));
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());

		MockHttpServletRequestBuilder request = post("/authorize").content("response_type=token&client_id=test-client")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&token_type=Bearer", accessToken.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_hybrid_get_minimumParams_isOk() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(testClient(new ResponseType(ResponseType.Value.CODE, ResponseType.Value.TOKEN)));
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get("/authorize?response_type=code token&client_id=test-client")
				.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com#access_token={accessToken}&code={code}&token_type=Bearer",
						accessToken.getValue(), authorizationCode.getValue()));
	}

	@Test
	@WithMockUser
	public void oAuth2_hybrid_post_minimumParams_isOk() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(testClient(new ResponseType(ResponseType.Value.CODE, ResponseType.Value.TOKEN)));
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = post("/authorize")
				.content("response_type=code token&client_id=test-client")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com#access_token={accessToken}&code={code}&token_type=Bearer",
						accessToken.getValue(), authorizationCode.getValue()));
	}

	// OIDC requests

	@Test
	@WithMockUser
	public void oidc_authCode_get_minimumParams_isOk() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(testClient(new ResponseType(ResponseType.Value.CODE)));
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new BearerAccessToken());
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(new PlainJWT(new JWTClaimsSet.Builder().build()));
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}&session_state={sessionState}",
						authorizationCode.getValue(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_authCode_post_minimumParams_isOk() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(testClient(new ResponseType(ResponseType.Value.CODE)));
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new BearerAccessToken());
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(new PlainJWT(new JWTClaimsSet.Builder().build()));
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = post("/authorize")
				.content("scope=openid&response_type=code&client_id=test-client&redirect_uri=http://example.com")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://example.com?code={code}&session_state={sessionState}",
						authorizationCode.getValue(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_implicit_get_minimumParams_isOk() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(testClient(new ResponseType(OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN)));
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&id_token={idToken}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), idToken.serialize(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_implicit_post_minimumParams_isOk() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());

		given(this.clientRepository.findByClientId(any(ClientID.class)))
				.willReturn(testClient(new ResponseType(OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN)));
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);

		MockHttpServletRequestBuilder request = post("/authorize").content(
				"scope=openid&response_type=id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&id_token={idToken}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), idToken.serialize(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_hybrid_get_minimumParams_isOk() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(testClient(
				new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN)));
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = get(
				"/authorize?scope=openid&response_type=code id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
						.session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&code={code}&id_token={idToken}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), authorizationCode.getValue(), idToken.serialize(), this.session.getId()));
	}

	@Test
	@WithMockUser
	public void oidc_hybrid_post_minimumParams_isOk() throws Exception {
		BearerAccessToken accessToken = new BearerAccessToken();
		JWT idToken = new PlainJWT(new JWTClaimsSet.Builder().build());
		AuthorizationCode authorizationCode = new AuthorizationCode();

		given(this.clientRepository.findByClientId(any(ClientID.class))).willReturn(testClient(
				new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN)));
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);
		given(this.tokenService.createRefreshToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(new RefreshToken());
		given(this.tokenService.createIdToken(any(AuthenticationRequest.class), any(UserDetails.class)))
				.willReturn(idToken);
		given(this.authorizationCodeService.create(any(AuthorizationCodeContext.class))).willReturn(authorizationCode);

		MockHttpServletRequestBuilder request = post("/authorize").content(
				"scope=openid&response_type=code id_token token&client_id=test-client&redirect_uri=http://example.com&nonce=test")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).session(this.session);
		this.mvc.perform(request).andExpect(status().isFound()).andExpect(redirectedUrl(
				"http://example.com#access_token={accessToken}&code={code}&id_token={idToken}&token_type=Bearer&session_state={sessionState}",
				accessToken.getValue(), authorizationCode.getValue(), idToken.serialize(), this.session.getId()));
	}

	// Misc requests

	@Test
	@WithMockUser
	public void get_noParams_isBadRequest() throws Exception {
		this.mvc.perform(get("/authorize")).andExpect(status().isBadRequest());
	}

	@Test
	@WithMockUser
	public void post_noParams_isBadRequest() throws Exception {
		this.mvc.perform(post("/authorize")).andExpect(status().isBadRequest());
	}

	private static OIDCClientInformation testClient(ResponseType responseType) {
		ClientID clientID = new ClientID("test-client");
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.applyDefaults();
		clientMetadata.setResponseTypes(Collections.singleton(responseType));
		clientMetadata.setRedirectionURI(URI.create("http://example.com"));
		Secret secret = new Secret("test-secret");

		return new OIDCClientInformation(clientID, new Date(), clientMetadata, secret);
	}

}
