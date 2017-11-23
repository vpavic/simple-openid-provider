package io.github.vpavic.oauth2.config;

import java.util.Objects;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.id.Issuer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import io.github.vpavic.oauth2.authentication.BearerAccessTokenAuthenticationFilter;
import io.github.vpavic.oauth2.endpoint.UserInfoEndpoint;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;

@Order(-1)
@Configuration
public class UserInfoSecurityConfiguration extends WebSecurityConfigurerAdapter {

	private final Issuer issuer;

	private final JwkSetLoader jwkSetLoader;

	private JWSAlgorithm accessTokenJwsAlgorithm = JWSAlgorithm.RS256;

	public UserInfoSecurityConfiguration(Issuer issuer, JwkSetLoader jwkSetLoader) {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(jwkSetLoader, "jwkSetLoader must not be null");

		this.issuer = issuer;
		this.jwkSetLoader = jwkSetLoader;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
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
			.addFilterBefore(userInfoAuthenticationFilter(), AbstractPreAuthenticatedProcessingFilter.class);
		// @formatter:on
	}

	public void setAccessTokenJwsAlgorithm(JWSAlgorithm accessTokenJwsAlgorithm) {
		this.accessTokenJwsAlgorithm = accessTokenJwsAlgorithm;
	}

	@Bean
	public BearerAccessTokenAuthenticationFilter userInfoAuthenticationFilter() {
		BearerAccessTokenAuthenticationFilter filter = new BearerAccessTokenAuthenticationFilter(this.issuer,
				this.jwkSetLoader);
		filter.setAccessTokenJwsAlgorithm(this.accessTokenJwsAlgorithm);
		return filter;
	}

}
