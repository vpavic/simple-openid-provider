package io.github.vpavic.oauth2;

import java.util.Collections;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;

import io.github.vpavic.oauth2.authorization.AuthorizationEndpoint;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;
import io.github.vpavic.oauth2.token.AccessTokenClaimsMapper;
import io.github.vpavic.oauth2.token.AuthorizationCodeService;
import io.github.vpavic.oauth2.token.DefaultTokenService;
import io.github.vpavic.oauth2.token.IdTokenClaimsMapper;
import io.github.vpavic.oauth2.token.RefreshTokenStore;
import io.github.vpavic.oauth2.token.TokenEndpoint;
import io.github.vpavic.oauth2.token.TokenRevocationEndpoint;
import io.github.vpavic.oauth2.token.TokenService;
import io.github.vpavic.oauth2.userinfo.BearerAccessTokenAuthenticationFilter;
import io.github.vpavic.oauth2.userinfo.UserInfoEndpoint;
import io.github.vpavic.oauth2.userinfo.UserInfoMapper;

@Configuration
public class CoreConfiguration {

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	private final JwkSetLoader jwkSetLoader;

	private final AuthenticationManager authenticationManager;

	private final AuthorizationCodeService authorizationCodeService;

	private final RefreshTokenStore refreshTokenStore;

	private final AccessTokenClaimsMapper accessTokenClaimsMapper;

	private final IdTokenClaimsMapper idTokenClaimsMapper;

	private final UserInfoMapper userInfoMapper;

	public CoreConfiguration(OpenIdProviderProperties properties,
			ObjectProvider<ClientRepository> clientRepository, ObjectProvider<JwkSetLoader> jwkSetLoader,
			ObjectProvider<AuthenticationManager> authenticationManager,
			ObjectProvider<AuthorizationCodeService> authorizationCodeService,
			ObjectProvider<RefreshTokenStore> refreshTokenStore,
			ObjectProvider<AccessTokenClaimsMapper> accessTokenClaimsMapper,
			ObjectProvider<IdTokenClaimsMapper> idTokenClaimsMapper, ObjectProvider<UserInfoMapper> userInfoMapper) {
		this.properties = properties;
		this.clientRepository = clientRepository.getObject();
		this.jwkSetLoader = jwkSetLoader.getObject();
		this.authenticationManager = authenticationManager.getObject();
		this.authorizationCodeService = authorizationCodeService.getObject();
		this.refreshTokenStore = refreshTokenStore.getObject();
		this.accessTokenClaimsMapper = accessTokenClaimsMapper.getObject();
		this.idTokenClaimsMapper = idTokenClaimsMapper.getObject();
		this.userInfoMapper = userInfoMapper.getObject();
	}

	@Bean
	public TokenService tokenService() {
		return new DefaultTokenService(this.properties, this.jwkSetLoader, this.refreshTokenStore);
	}

	@Bean
	public AuthorizationEndpoint authorizationEndpoint() {
		AuthorizationEndpoint authorizationEndpoint = new AuthorizationEndpoint(this.clientRepository, this.authorizationCodeService,
				tokenService(), this.accessTokenClaimsMapper, this.idTokenClaimsMapper, this.userInfoMapper);
		authorizationEndpoint.setAcr(this.properties.getAuthorization().getAcrs().get(0));
		authorizationEndpoint.setSessionManagementEnabled(this.properties.getSessionManagement().isEnabled());
		authorizationEndpoint.setSupportedScopes(this.properties.getAuthorization().getSupportedScopes());
		return authorizationEndpoint;
	}

	@Bean
	public TokenEndpoint tokenEndpoint() {
		return new TokenEndpoint(this.properties, this.clientRepository, this.authorizationCodeService, tokenService(),
				this.authenticationManager, this.refreshTokenStore, this.accessTokenClaimsMapper,
				this.idTokenClaimsMapper);
	}

	@Bean
	public TokenRevocationEndpoint tokenRevocationEndpoint() {
		return new TokenRevocationEndpoint(this.properties, this.clientRepository, this.refreshTokenStore);
	}

	@Bean
	public UserInfoEndpoint userInfoEndpoint() {
		return new UserInfoEndpoint(this.userInfoMapper);
	}

	@Order(0)
	@Configuration
	public static class TokenSecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatchers()
					.antMatchers(HttpMethod.POST, TokenEndpoint.PATH_MAPPING, TokenRevocationEndpoint.PATH_MAPPING)
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

	@Order(-1)
	@Configuration
	public static class UserInfoSecurityConfiguration extends WebSecurityConfigurerAdapter {

		private final OpenIdProviderProperties properties;

		private final UserDetailsService userDetailsService;

		private final JwkSetLoader jwkSetLoader;

		UserInfoSecurityConfiguration(OpenIdProviderProperties properties,
				ObjectProvider<UserDetailsService> userDetailsService, ObjectProvider<JwkSetLoader> jwkSetLoader) {
			this.properties = properties;
			this.userDetailsService = userDetailsService.getObject();
			this.jwkSetLoader = jwkSetLoader.getObject();
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
			authenticationProvider.setPreAuthenticatedUserDetailsService(
					new UserDetailsByNameServiceWrapper<>(this.userDetailsService));

			AuthenticationManager authenticationManager = new ProviderManager(
					Collections.singletonList(authenticationProvider));

			BearerAccessTokenAuthenticationFilter authenticationFilter = new BearerAccessTokenAuthenticationFilter(
					this.properties, this.jwkSetLoader, authenticationManager);

			// @formatter:off
			http
				.antMatcher(UserInfoEndpoint.PATH_MAPPING)
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.cors()
					.and()
				.csrf()
					.disable()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
					.and()
				.addFilterBefore(authenticationFilter, AbstractPreAuthenticatedProcessingFilter.class);
			// @formatter:on
		}

	}

}
