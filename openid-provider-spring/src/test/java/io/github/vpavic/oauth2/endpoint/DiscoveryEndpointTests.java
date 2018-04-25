package io.github.vpavic.oauth2.endpoint;

import java.net.URI;
import java.util.Collections;

import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link DiscoveryEndpoint}.
 */
@ExtendWith(SpringExtension.class)
@WebAppConfiguration
@ContextConfiguration
class DiscoveryEndpointTests {

	@Autowired
	private WebApplicationContext wac;

	private MockMvc mvc;

	@BeforeEach
	void setUp() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
	}

	@Test
	void getProviderMetadata() throws Exception {
		this.mvc.perform(get("/.well-known/openid-configuration")).andExpect(status().isOk())
				.andExpect(jsonPath("$.issuer").value("http://example.com"))
				.andExpect(jsonPath("$.subject_types_supported").value("public"))
				.andExpect(jsonPath("$.jwks_uri").value("http://example.com/jwks.json"));
	}

	@Configuration
	@EnableWebMvc
	static class Config {

		@Bean
		public DiscoveryHandler discoveryEndpointHandler() {
			return new DiscoveryHandler(new OIDCProviderMetadata(new Issuer("http://example.com"),
					Collections.singletonList(SubjectType.PUBLIC), URI.create("http://example.com/jwks.json")));
		}

		@Bean
		public DiscoveryEndpoint discoveryEndpoint() {
			return new DiscoveryEndpoint(discoveryEndpointHandler());
		}

	}

}
