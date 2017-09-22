package io.github.vpavic.op.config;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("op")
public class OpenIdProviderProperties {

	private String issuer = "http://localhost:6432";

	private final Jwk jwk = new Jwk();

	private final Registration registration = new Registration();

	private final IdToken idToken = new IdToken();

	private final Authorization authorization = new Authorization();

	private final AuthorizationCode code = new AuthorizationCode();

	private final AccessToken accessToken = new AccessToken();

	private final RefreshToken refreshToken = new RefreshToken();

	private final SessionManagement sessionManagement = new SessionManagement();

	private final FrontChannelLogout frontChannelLogout = new FrontChannelLogout();

	public String getIssuer() {
		return this.issuer;
	}

	public void setIssuer(String issuer) {
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

	public static class Jwk {

		private int retentionPeriod = 30;

		public int getRetentionPeriod() {
			return this.retentionPeriod;
		}

		public void setRetentionPeriod(int retentionPeriod) {
			this.retentionPeriod = retentionPeriod;
		}

	}

	public static class Registration {

		private boolean enabled;

		private boolean updateSecret;

		private boolean updateAccessToken;

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
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

	public static class IdToken {

		private int lifetime = 900;

		public int getLifetime() {
			return this.lifetime;
		}

		public void setLifetime(int lifetime) {
			this.lifetime = lifetime;
		}

	}

	public static class Authorization {

		private List<String> openidScopes = Arrays.asList(OIDCScopeValue.OPENID.getValue(),
				OIDCScopeValue.OFFLINE_ACCESS.getValue());

		private Map<String, String> resourceScopes = new HashMap<>();

		private List<String> acrs = Collections.singletonList("1");

		public List<String> getOpenidScopes() {
			return this.openidScopes;
		}

		public void setOpenidScopes(List<String> openidScopes) {
			this.openidScopes = openidScopes;
		}

		public Map<String, String> getResourceScopes() {
			return this.resourceScopes;
		}

		public List<String> getAcrs() {
			return this.acrs;
		}

		public void setAcrs(List<String> acrs) {
			this.acrs = acrs;
		}

	}

	public static class AuthorizationCode {

		private int lifetime = 600;

		public int getLifetime() {
			return this.lifetime;
		}

		public void setLifetime(int lifetime) {
			this.lifetime = lifetime;
		}

	}

	public static class AccessToken {

		private int lifetime = 600;

		public int getLifetime() {
			return this.lifetime;
		}

		public void setLifetime(int lifetime) {
			this.lifetime = lifetime;
		}

	}

	public static class RefreshToken {

		private int lifetime;

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

	public static class SessionManagement {

		private boolean enabled;

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

	}

	public static class FrontChannelLogout {

		private boolean enabled;

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

	}

}
