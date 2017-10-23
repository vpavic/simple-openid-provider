package io.github.vpavic.op.config;

import com.hazelcast.core.HazelcastInstance;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcOperations;

import io.github.vpavic.oauth2.OpenIdProviderConfiguration;
import io.github.vpavic.oauth2.OpenIdProviderProperties;
import io.github.vpavic.oauth2.authorization.AuthorizationConfiguration;
import io.github.vpavic.oauth2.checksession.CheckSessionConfiguration;
import io.github.vpavic.oauth2.client.ClientRegistrationConfiguration;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.client.jdbc.JdbcClientRepository;
import io.github.vpavic.oauth2.discovery.DiscoveryConfiguration;
import io.github.vpavic.oauth2.endsession.EndSessionConfiguration;
import io.github.vpavic.oauth2.jwk.JwkSetStore;
import io.github.vpavic.oauth2.jwk.jdbc.JdbcJwkSetStore;
import io.github.vpavic.oauth2.token.AccessTokenClaimsMapper;
import io.github.vpavic.oauth2.token.AuthorizationCodeService;
import io.github.vpavic.oauth2.token.IdTokenClaimsMapper;
import io.github.vpavic.oauth2.token.RefreshTokenStore;
import io.github.vpavic.oauth2.token.TokenConfiguration;
import io.github.vpavic.oauth2.token.hazelcast.HazelcastAuthorizationCodeService;
import io.github.vpavic.oauth2.token.jdbc.JdbcRefreshTokenStore;
import io.github.vpavic.oauth2.userinfo.UserInfoConfiguration;
import io.github.vpavic.oauth2.userinfo.UserInfoMapper;
import io.github.vpavic.op.oauth2.NullAccessTokenClaimsMapper;
import io.github.vpavic.op.oauth2.NullIdTokenClaimsMapper;
import io.github.vpavic.op.oauth2.SubjectUserInfoMapper;

@Configuration
@Import({ AuthorizationConfiguration.class, CheckSessionConfiguration.class, ClientRegistrationConfiguration.class,
		DiscoveryConfiguration.class, EndSessionConfiguration.class, OpenIdProviderConfiguration.class,
		TokenConfiguration.class, UserInfoConfiguration.class })
public class OAuth2Configuration {

	private final OpenIdProviderProperties properties;

	private final JdbcOperations jdbcOperations;

	private final HazelcastInstance hazelcastInstance;

	public OAuth2Configuration(OpenIdProviderProperties properties, ObjectProvider<JdbcOperations> jdbcOperations,
			ObjectProvider<HazelcastInstance> hazelcastInstance) {
		this.properties = properties;
		this.jdbcOperations = jdbcOperations.getObject();
		this.hazelcastInstance = hazelcastInstance.getObject();
	}

	@Bean
	public ClientRepository clientRepository() {
		return new JdbcClientRepository(this.jdbcOperations);
	}

	@Bean
	public JwkSetStore jwkSetStore() {
		return new JdbcJwkSetStore(this.properties, this.jdbcOperations);
	}

	@Bean
	public RefreshTokenStore refreshTokenStore() {
		return new JdbcRefreshTokenStore(this.jdbcOperations);
	}

	@Bean
	public AuthorizationCodeService authorizationCodeService() {
		return new HazelcastAuthorizationCodeService(this.properties, this.hazelcastInstance);
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
	public UserInfoMapper userInfoMapper() {
		return new SubjectUserInfoMapper();
	}

}
