package io.github.vpavic.op.oauth2.token;

import com.hazelcast.core.HazelcastInstance;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import io.github.vpavic.op.config.OpenIdProviderProperties;
import io.github.vpavic.op.oauth2.client.ClientRepository;
import io.github.vpavic.op.oauth2.jwk.JwkSetLoader;

@Configuration
public class TokenConfiguration {

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	private final JwkSetLoader jwkSetLoader;

	private final AuthenticationManager authenticationManager;

	private final HazelcastInstance hazelcastInstance;

	private final JdbcOperations jdbcOperations;

	public TokenConfiguration(OpenIdProviderProperties properties, ObjectProvider<ClientRepository> clientRepository,
			ObjectProvider<JwkSetLoader> jwkSetLoader, ObjectProvider<AuthenticationManager> authenticationManager,
			ObjectProvider<HazelcastInstance> hazelcastInstance, ObjectProvider<JdbcOperations> jdbcOperations) {
		this.properties = properties;
		this.clientRepository = clientRepository.getObject();
		this.jwkSetLoader = jwkSetLoader.getObject();
		this.authenticationManager = authenticationManager.getObject();
		this.hazelcastInstance = hazelcastInstance.getObject();
		this.jdbcOperations = jdbcOperations.getObject();
	}

	@Bean
	public AuthorizationCodeService authorizationCodeService() {
		return new HazelcastAuthorizationCodeService(this.properties, this.hazelcastInstance);
	}

	@Bean
	public RefreshTokenStore refreshTokenStore() {
		return new JdbcRefreshTokenStore(this.jdbcOperations);
	}

	@Bean
	public TokenService tokenService() {
		return new DefaultTokenService(this.properties, this.jwkSetLoader, refreshTokenStore());
	}

	@Bean
	public AccessTokenClaimsMapper accessTokenClaimsMapper() {
		return new NullAccessTokenClaimsMapper();
	}

	@Bean
	public IdTokenClaimsMapper idTokenClaimsMapper() {
		return new NullIdTokenClaimsMapper();
	}

	@Bean
	public TokenEndpoint tokenEndpoint() {
		return new TokenEndpoint(this.properties, this.clientRepository, authorizationCodeService(), tokenService(),
				this.authenticationManager, refreshTokenStore(), accessTokenClaimsMapper(), idTokenClaimsMapper());
	}

	@Bean
	public TokenRevocationEndpoint tokenRevocationEndpoint() {
		return new TokenRevocationEndpoint(this.properties, this.clientRepository, refreshTokenStore());
	}

	@Order(97)
	@Configuration
	static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatchers()
					.antMatchers(TokenEndpoint.PATH_MAPPING, TokenRevocationEndpoint.PATH_MAPPING)
					.and()
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.csrf()
					.disable()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			// @formatter:on
		}

	}

}
