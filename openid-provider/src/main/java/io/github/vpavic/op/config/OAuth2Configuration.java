package io.github.vpavic.op.config;

import java.io.IOException;
import java.text.ParseException;
import java.time.Duration;

import com.hazelcast.core.HazelcastInstance;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.util.FileCopyUtils;

import io.github.vpavic.oauth2.OpenIdProviderConfiguration;
import io.github.vpavic.oauth2.OpenIdProviderProperties;
import io.github.vpavic.oauth2.claim.ClaimSource;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.client.JdbcClientRepository;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeService;
import io.github.vpavic.oauth2.grant.code.HazelcastAuthorizationCodeService;
import io.github.vpavic.oauth2.grant.refresh.JdbcRefreshTokenStore;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenStore;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;

@Configuration
@Import(OpenIdProviderConfiguration.class)
public class OAuth2Configuration {

	private static final String JWK_SET_LOCATION = "classpath:jwks.json";

	private final ResourceLoader resourceLoader;

	private final OpenIdProviderProperties properties;

	private final JdbcOperations jdbcOperations;

	private final HazelcastInstance hazelcastInstance;

	public OAuth2Configuration(ResourceLoader resourceLoader, OpenIdProviderProperties properties,
			ObjectProvider<JdbcOperations> jdbcOperations, ObjectProvider<HazelcastInstance> hazelcastInstance) {
		this.resourceLoader = resourceLoader;
		this.properties = properties;
		this.jdbcOperations = jdbcOperations.getObject();
		this.hazelcastInstance = hazelcastInstance.getObject();
	}

	@Bean
	public ClientRepository clientRepository() {
		return new JdbcClientRepository(this.jdbcOperations);
	}

	@Bean
	public JwkSetLoader jwkSetLoader() {
		return () -> {
			try {
				Resource jwkSetResource = this.resourceLoader.getResource(JWK_SET_LOCATION);
				String jwkSetJson = new String(FileCopyUtils.copyToByteArray(jwkSetResource.getInputStream()));

				return JWKSet.parse(jwkSetJson);
			}
			catch (IOException | ParseException e) {
				throw new RuntimeException(e);
			}
		};
	}

	@Bean
	public RefreshTokenStore refreshTokenStore() {
		return new JdbcRefreshTokenStore(this.jdbcOperations);
	}

	@Bean
	public AuthorizationCodeService authorizationCodeService() {
		HazelcastAuthorizationCodeService authorizationCodeService = new HazelcastAuthorizationCodeService(
				this.hazelcastInstance);
		authorizationCodeService.setCodeLifetime(Duration.ofSeconds(this.properties.getCode().getLifetime()));
		return authorizationCodeService;
	}

	@Bean
	public ClaimSource claimSource() {
		return (subject, claims) -> new UserInfo(subject);
	}

}
