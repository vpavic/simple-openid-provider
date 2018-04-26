package io.github.vpavic.op.config;

import java.io.IOException;
import java.text.ParseException;
import java.time.Duration;

import com.hazelcast.core.HazelcastInstance;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import io.github.vpavic.oauth2.OpenIdProviderConfiguration;
import io.github.vpavic.oauth2.OpenIdProviderProperties;
import io.github.vpavic.oauth2.claim.ClaimSource;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.client.JdbcClientRepository;
import io.github.vpavic.oauth2.grant.code.AuthorizationCodeService;
import io.github.vpavic.oauth2.grant.code.HazelcastAuthorizationCodeService;
import io.github.vpavic.oauth2.grant.password.PasswordAuthenticationHandler;
import io.github.vpavic.oauth2.grant.refresh.JdbcRefreshTokenStore;
import io.github.vpavic.oauth2.grant.refresh.RefreshTokenStore;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;
import io.github.vpavic.oauth2.scope.DefaultScopeResolver;
import io.github.vpavic.oauth2.scope.ScopeResolver;

@Configuration
@Import(OpenIdProviderConfiguration.class)
public class OAuth2Configuration {

	private static final String JWK_SET_LOCATION = "classpath:jwks.json";

	private final ResourceLoader resourceLoader;

	private final OpenIdProviderProperties properties;

	private final JdbcOperations jdbcOperations;

	private final AuthenticationManager authenticationManager;

	private final HazelcastInstance hazelcastInstance;

	public OAuth2Configuration(ResourceLoader resourceLoader, OpenIdProviderProperties properties,
			ObjectProvider<JdbcOperations> jdbcOperations, ObjectProvider<AuthenticationManager> authenticationManager,
			ObjectProvider<HazelcastInstance> hazelcastInstance) {
		this.resourceLoader = resourceLoader;
		this.properties = properties;
		this.jdbcOperations = jdbcOperations.getObject();
		this.authenticationManager = authenticationManager.getObject();
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
				return JWKSet.load(jwkSetResource.getInputStream());
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

	@Bean
	public ScopeResolver scopeResolver() {
		DefaultScopeResolver scopeResolver = new DefaultScopeResolver();
		scopeResolver.setSupportedScopes(this.properties.getAuthorization().getSupportedScopes());
		return scopeResolver;
	}

	@Bean
	public PasswordAuthenticationHandler passwordAuthenticationHandler() {
		return grant -> {
			try {
				Authentication authentication = this.authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(grant.getUsername(), grant.getPassword().getValue()));
				return new Subject(authentication.getName());
			}
			catch (AuthenticationException e) {
				throw new GeneralException(OAuth2Error.INVALID_GRANT);
			}
		};
	}

}
