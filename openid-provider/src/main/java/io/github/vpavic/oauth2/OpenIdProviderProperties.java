package io.github.vpavic.oauth2;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import org.hibernate.validator.constraints.Range;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration properties for OpenID Provider.
 *
 * @author Vedran Pavic
 */
@ConfigurationProperties("op")
@Validated
public class OpenIdProviderProperties {

	/**
	 * Issuer Identifier. A case sensitive URL that contains scheme, host, and optionally, port number and path
	 * components and no query or fragment components.
	 */
	private Issuer issuer = new Issuer("http://127.0.0.1:6432");

	@Valid
	private final Jwk jwk = new Jwk();

	@Valid
	private final Registration registration = new Registration();

	@Valid
	private final IdToken idToken = new IdToken();

	@Valid
	private final Authorization authorization = new Authorization();

	@Valid
	private final AuthorizationCode code = new AuthorizationCode();

	@Valid
	private final AccessToken accessToken = new AccessToken();

	@Valid
	private final RefreshToken refreshToken = new RefreshToken();

	@Valid
	private final SessionManagement sessionManagement = new SessionManagement();

	@Valid
	private final FrontChannelLogout frontChannelLogout = new FrontChannelLogout();

	public Issuer getIssuer() {
		return this.issuer;
	}

	public void setIssuer(Issuer issuer) {
		this.issuer = issuer;
	}

	public Jwk getJwk() {
		return this.jwk;
	}

	public Registration getRegistration() {
		return this.registration;
	}

	public IdToken getIdToken() {
		return this.idToken;
	}

	public Authorization getAuthorization() {
		return this.authorization;
	}

	public AuthorizationCode getCode() {
		return this.code;
	}

	public AccessToken getAccessToken() {
		return this.accessToken;
	}

	public RefreshToken getRefreshToken() {
		return this.refreshToken;
	}

	public SessionManagement getSessionManagement() {
		return this.sessionManagement;
	}

	public FrontChannelLogout getFrontChannelLogout() {
		return this.frontChannelLogout;
	}

	public boolean isLogoutEnabled() {
		return this.sessionManagement.isEnabled() || this.frontChannelLogout.isEnabled();
	}

	@Validated
	public static class Jwk {

		/**
		 * The retention period for decommissioned JWKs, in seconds.
		 */
		@Range(min = 1, max = 3600)
		private int retentionPeriod = 1200;

		public int getRetentionPeriod() {
			return this.retentionPeriod;
		}

		public void setRetentionPeriod(int retentionPeriod) {
			this.retentionPeriod = retentionPeriod;
		}

	}

	@Validated
	public static class Registration {

		/**
		 * Enable open Dynamic Registration.
		 */
		private boolean openRegistrationEnabled;

		/**
		 * Master access token for Dynamic Registration.
		 */
		private BearerAccessToken apiAccessToken;

		/**
		 * Enable update of Client secret on registration update.
		 */
		private boolean updateSecret;

		/**
		 * Enable update of Client access token on registration update.
		 */
		private boolean updateAccessToken;

		public boolean isOpenRegistrationEnabled() {
			return this.openRegistrationEnabled;
		}

		public void setOpenRegistrationEnabled(boolean openRegistrationEnabled) {
			this.openRegistrationEnabled = openRegistrationEnabled;
		}

		public BearerAccessToken getApiAccessToken() {
			return this.apiAccessToken;
		}

		public void setApiAccessToken(BearerAccessToken apiAccessToken) {
			this.apiAccessToken = apiAccessToken;
		}

		public boolean isUpdateSecret() {
			return this.updateSecret;
		}

		public void setUpdateSecret(boolean updateSecret) {
			this.updateSecret = updateSecret;
		}

		public boolean isUpdateAccessToken() {
			return this.updateAccessToken;
		}

		public void setUpdateAccessToken(boolean updateAccessToken) {
			this.updateAccessToken = updateAccessToken;
		}

	}

	@Validated
	public static class IdToken {

		/**
		 * The default ID Token lifetime, in seconds.
		 */
		@Range(min = 1, max = 3600)
		private int lifetime = 900;

		public int getLifetime() {
			return this.lifetime;
		}

		public void setLifetime(int lifetime) {
			this.lifetime = lifetime;
		}

	}

	@Validated
	public static class Authorization {

		/**
		 * Comma-separated list of supported OpenID scopes.
		 */
		@NotEmpty
		private List<Scope.Value> openidScopes = Arrays.asList(OIDCScopeValue.OPENID, OIDCScopeValue.OFFLINE_ACCESS);

		/**
		 * Mappings of resource scopes to resource IDs.
		 */
		private Map<Scope.Value, String> resourceScopes = new HashMap<>();

		/**
		 * Comma-separated list of supported ACRs.
		 */
		@NotEmpty
		private List<ACR> acrs = Collections.singletonList(new ACR("1"));

		public List<Scope.Value> getOpenidScopes() {
			return this.openidScopes;
		}

		public void setOpenidScopes(List<Scope.Value> openidScopes) {
			this.openidScopes = openidScopes;
		}

		public Map<Scope.Value, String> getResourceScopes() {
			return this.resourceScopes;
		}

		public List<ACR> getAcrs() {
			return this.acrs;
		}

		public void setAcrs(List<ACR> acrs) {
			this.acrs = acrs;
		}

		public Scope getSupportedScope() {
			Scope supportedScope = new Scope();
			this.openidScopes.forEach(value -> supportedScope.add(value.getValue()));
			this.resourceScopes.keySet().forEach(value -> supportedScope.add(value.getValue()));

			return supportedScope;
		}

	}

	@Validated
	public static class AuthorizationCode {

		/**
		 * The default Authorization Code lifetime, in seconds.
		 */
		@Range(min = 1, max = 600)
		private int lifetime = 300;

		public int getLifetime() {
			return this.lifetime;
		}

		public void setLifetime(int lifetime) {
			this.lifetime = lifetime;
		}

	}

	@Validated
	public static class AccessToken {

		/**
		 * The default Access Token lifetime, in seconds.
		 */
		@Range(min = 1, max = 3600)
		private int lifetime = 600;

		public int getLifetime() {
			return this.lifetime;
		}

		public void setLifetime(int lifetime) {
			this.lifetime = lifetime;
		}

	}

	@Validated
	public static class RefreshToken {

		/**
		 * The default Refresh Token lifetime, in seconds, zero implies no expiration.
		 */
		@Range(min = 0, max = Integer.MAX_VALUE)
		private int lifetime;

		/**
		 * Enable update of Refresh Token on refresh request.
		 */
		private boolean update;

		public int getLifetime() {
			return this.lifetime;
		}

		public void setLifetime(int lifetime) {
			this.lifetime = lifetime;
		}

		public boolean isUpdate() {
			return this.update;
		}

		public void setUpdate(boolean update) {
			this.update = update;
		}

	}

	@Validated
	public static class SessionManagement {

		/**
		 * Enable OpenID Connect Session Management support.
		 */
		private boolean enabled;

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

	}

	@Validated
	public static class FrontChannelLogout {

		/**
		 * Enable OpenID Connect Front-Channel Logout support.
		 */
		private boolean enabled;

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

	}

}
