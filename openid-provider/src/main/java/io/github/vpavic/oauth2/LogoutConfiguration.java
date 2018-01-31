package io.github.vpavic.oauth2;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.servlet.server.Session;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;

import io.github.vpavic.oauth2.LogoutConfiguration.LogoutCondition;
import io.github.vpavic.oauth2.client.ClientRepository;
import io.github.vpavic.oauth2.endpoint.CheckSessionHandler;
import io.github.vpavic.oauth2.endpoint.CheckSessionIframe;
import io.github.vpavic.oauth2.endpoint.EndSessionEndpoint;
import io.github.vpavic.oauth2.endpoint.EndSessionHandler;

@Configuration
@Conditional(LogoutCondition.class)
public class LogoutConfiguration {

	private final Session.Cookie sessionCookieProperties;

	private final OpenIdProviderProperties providerProperties;

	private final ClientRepository clientRepository;

	public LogoutConfiguration(ServerProperties serverProperties, OpenIdProviderProperties providerProperties,
			ObjectProvider<ClientRepository> clientRepository) {
		this.sessionCookieProperties = serverProperties.getServlet().getSession().getCookie();
		this.providerProperties = providerProperties;
		this.clientRepository = clientRepository.getObject();
	}

	@Bean
	public EndSessionEndpoint endSessionEndpoint() {
		EndSessionHandler handler = new EndSessionHandler(this.providerProperties.getIssuer(), this.clientRepository);
		handler.setFrontChannelLogoutEnabled(this.providerProperties.getFrontChannelLogout().isEnabled());
		return new EndSessionEndpoint(handler);
	}

	@Bean
	@Conditional(SessionManagementCondition.class)
	public CheckSessionIframe checkSessionIframe() {
		CheckSessionHandler handler = new CheckSessionHandler(this.sessionCookieProperties.getName());
		return new CheckSessionIframe(handler);
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
