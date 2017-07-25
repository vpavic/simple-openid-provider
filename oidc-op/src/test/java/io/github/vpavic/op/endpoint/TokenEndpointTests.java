package io.github.vpavic.op.endpoint;

import java.util.HashMap;
import java.util.Map;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
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

import io.github.vpavic.op.code.AuthorizationCodeService;
import io.github.vpavic.op.token.TokenService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
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
		AuthorizationCode authorizationCode = new AuthorizationCode();
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(createAuthContext());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);

		MockHttpServletRequestBuilder request = post("/token")
				.content("grant_type=authorization_code&code=" + authorizationCode.getValue()
						+ "&redirect_uri=http://example.com")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).header("Authorization",
						new ClientSecretBasic(new ClientID("test"), new Secret("test")).toHTTPAuthorizationHeader());
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void authCode_postAuth_isOk() throws Exception {
		AuthorizationCode authorizationCode = new AuthorizationCode();
		BearerAccessToken accessToken = new BearerAccessToken();

		given(this.authorizationCodeService.consume(eq(authorizationCode))).willReturn(createAuthContext());
		given(this.tokenService.createAccessToken(any(AuthorizationRequest.class), any(UserDetails.class)))
				.willReturn(accessToken);

		MockHttpServletRequestBuilder request = post("/token")
				.content("grant_type=authorization_code&code=" + authorizationCode.getValue()
						+ "&redirect_uri=http://example.com&client_id=test-id&client_secret=test-secret")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void noParams_isBadRequest() throws Exception {
		this.mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED))
				.andExpect(status().isBadRequest());
	}

	@SuppressWarnings("unchecked")
	private static <K, V> Map<K, V> createAuthContext() {
		Map<String, Object> authContext = new HashMap<>();
		authContext.put("authRequest", mock(AuthorizationRequest.class));
		authContext.put("authentication",
				new TestingAuthenticationToken(new User("test", "n/a", AuthorityUtils.NO_AUTHORITIES), "n/a"));
		return (Map<K, V>) authContext;
	}

}
