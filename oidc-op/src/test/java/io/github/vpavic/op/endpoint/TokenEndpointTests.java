package io.github.vpavic.op.endpoint;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import io.github.vpavic.op.code.AuthorizationCodeService;

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

	@Test
	public void tokenRequest_authCodeGrantType_isOk() throws Exception {
		String authorizationCode = "test";
		given(this.authorizationCodeService.consume(eq(new AuthorizationCode(authorizationCode))))
				.willReturn(new Tokens(new BearerAccessToken(), null));

		MockHttpServletRequestBuilder request = post("/token")
				.content("grant_type=authorization_code&redirect_uri=http://example.com&code=" + authorizationCode)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).header("Authorization",
						new ClientSecretBasic(new ClientID("test"), new Secret("test")).toHTTPAuthorizationHeader());
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void tokenRequest_withNoParams_isBadRequest() throws Exception {
		this.mvc.perform(post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED))
				.andExpect(status().isBadRequest());
	}

}
