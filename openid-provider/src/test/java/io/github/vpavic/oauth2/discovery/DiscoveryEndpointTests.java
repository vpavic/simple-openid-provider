package io.github.vpavic.oauth2.discovery;

import java.net.URI;
import java.util.Collections;

import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import io.github.vpavic.oauth2.DiscoveryConfiguration;

import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link DiscoveryEndpoint}.
 *
 * @author Vedran Pavic
 */
@RunWith(SpringRunner.class)
@WebMvcTest(DiscoveryEndpoint.class)
@Import(DiscoveryConfiguration.SecurityConfiguration.class)
public class DiscoveryEndpointTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Autowired
	private MockMvc mvc;

	@MockBean
	private OIDCProviderMetadata providerMetadata;

	@Test
	public void getProviderMetadata() throws Exception {
		given(this.providerMetadata.toJSONObject()).willReturn(
				new OIDCProviderMetadata(new Issuer("http://127.0.0.1"), Collections.singletonList(SubjectType.PUBLIC),
						URI.create("http://127.0.0.1/jwks.json")).toJSONObject());

		this.mvc.perform(get("/.well-known/openid-configuration")).andExpect(status().isOk())
				.andExpect(jsonPath("$.issuer").value("http://127.0.0.1"))
				.andExpect(jsonPath("$.subject_types_supported").value("public"))
				.andExpect(jsonPath("$.jwks_uri").value("http://127.0.0.1/jwks.json"));
	}

}
