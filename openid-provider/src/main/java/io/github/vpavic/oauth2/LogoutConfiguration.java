package io.github.vpavic.oauth2;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import io.github.vpavic.oauth2.LogoutConfiguration.LogoutCondition;
import io.github.vpavic.oauth2.checksession.CheckSessionIframe;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.endsession.EndSessionEndpoint;

@Configuration
@Conditional(LogoutCondition.class)
public class LogoutConfiguration {

	private final OpenIdProviderProperties properties;

	private final ClientRepository clientRepository;

	public LogoutConfiguration(OpenIdProviderProperties properties, ObjectProvider<ClientRepository> clientRepository) {
		this.properties = properties;
		this.clientRepository = clientRepository.getObject();
	}

	@Bean
	public EndSessionEndpoint endSessionEndpoint() {
		EndSessionEndpoint endpoint = new EndSessionEndpoint(this.properties.getIssuer(), this.clientRepository);
		endpoint.setFrontChannelLogoutEnabled(this.properties.getFrontChannelLogout().isEnabled());
		return endpoint;
	}

	@Bean
	@Conditional(SessionManagementCondition.class)
	public CheckSessionIframe checkSessionIframe() {
		return new CheckSessionIframe();
	}

	@Order(-3)
	@Configuration
	public static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatchers()
					.antMatchers(HttpMethod.GET, CheckSessionIframe.PATH_MAPPING)
					.and()
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.headers()
					.frameOptions().disable()
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			// @formatter:on
		}

	}

	private static class SessionManagementCondition extends SpringBootCondition {

		@Override
		public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
			ConditionMessage.Builder message = ConditionMessage.forCondition("OpenID Session Management Condition");
			Environment environment = context.getEnvironment();
			boolean enabled = environment.getProperty("op.session-management.enabled", Boolean.class, false);

			if (enabled) {
				return ConditionOutcome.match(message.found("property", "properties")
						.items(ConditionMessage.Style.QUOTE, "op.session-management.enabled"));
			}
			else {
				return ConditionOutcome.noMatch(message.didNotFind("property", "properties")
						.items(ConditionMessage.Style.QUOTE, "op.session-management.enabled"));
			}
		}

	}

	private static class FrontChannelLogoutCondition extends SpringBootCondition {

		@Override
		public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
			ConditionMessage.Builder message = ConditionMessage.forCondition("OpenID Front-Channel Logout Condition");
			Environment environment = context.getEnvironment();
			boolean enabled = environment.getProperty("op.front-channel-logout.enabled", Boolean.class, false);

			if (enabled) {
				return ConditionOutcome.match(message.found("property", "properties")
						.items(ConditionMessage.Style.QUOTE, "op.front-channel-logout.enabled"));
			}
			else {
				return ConditionOutcome.noMatch(message.didNotFind("property", "properties")
						.items(ConditionMessage.Style.QUOTE, "op.front-channel-logout.enabled"));
			}
		}

	}

	static class LogoutCondition extends AnyNestedCondition {

		LogoutCondition() {
			super(ConfigurationPhase.PARSE_CONFIGURATION);
		}

		@Conditional(SessionManagementCondition.class)
		static class SessionManagementEnabled {

		}

		@Conditional(FrontChannelLogoutCondition.class)
		static class FrontChannelLogoutEnabled {

		}

	}

}
