package io.github.vpavic.op.config;

import java.time.Duration;

import com.hazelcast.core.HazelcastInstance;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.jdbc.core.JdbcOperations;

import io.github.vpavic.oauth2.EnableOpenIdProvider;
import io.github.vpavic.oauth2.OpenIdProviderProperties;
import io.github.vpavic.oauth2.claim.UserClaimsLoader;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.client.jdbc.JdbcClientRepository;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;
import io.github.vpavic.oauth2.jwk.ResourceJwkSetLoader;
import io.github.vpavic.oauth2.token.AuthorizationCodeService;
import io.github.vpavic.oauth2.token.RefreshTokenStore;
import io.github.vpavic.oauth2.token.hazelcast.HazelcastAuthorizationCodeService;
import io.github.vpavic.oauth2.token.jdbc.JdbcRefreshTokenStore;

@Configuration
@EnableOpenIdProvider
public class OAuth2Configuration {

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
		return new ResourceJwkSetLoader(this.resourceLoader.getResource("classpath:jwks.json"));
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
	public UserClaimsLoader userClaimsLoader() {
		return (subject, scope) -> new UserInfo(subject);
	}

}
