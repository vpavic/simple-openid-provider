package io.github.vpavic.oauth2;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;

import com.nimbusds.jose.JWSAlgorithm;
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
	private final Registration registration = new Registration();

	@Valid
	private final Authorization authorization = new Authorization();

	@Valid
	private final AuthorizationCode code = new AuthorizationCode();

	@Valid
	private final AccessToken accessToken = new AccessToken();

	@Valid
	private final RefreshToken refreshToken = new RefreshToken();

	@Valid
	private final IdToken idToken = new IdToken();

	@Valid
	private final Claim claim = new Claim();

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

	public Registration getRegistration() {
		return this.registration;
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

	public IdToken getIdToken() {
		return this.idToken;
	}

	public Claim getClaim() {
		return this.claim;
	}

	public SessionManagement getSessionManagement() {
		return this.sessionManagement;
	}

	public FrontChannelLogout getFrontChannelLogout() {
		return this.frontChannelLogout;
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
	public static class Authorization {

		/**
		 * Comma-separated list of supported OpenID scopes.
		 */
		@NotEmpty
		private List<Scope.Value> openidScopes = Collections.singletonList(OIDCScopeValue.OPENID);

		/**
		 * Mappings of resource scopes to resource IDs.
		 */
		private Map<Scope.Value, String> resourceScopes = new HashMap<>();

		/**
		 * Mappings of supported levels of assurance to ACRs.
		 */
		@NotEmpty
		private Map<Integer, ACR> acrs = defaultAcrs();

		public List<Scope.Value> getOpenidScopes() {
			return this.openidScopes;
		}

		public void setOpenidScopes(List<Scope.Value> openidScopes) {
			this.openidScopes = openidScopes;
		}

		public Map<Scope.Value, String> getResourceScopes() {
			return this.resourceScopes;
		}

		public Map<Integer, ACR> getAcrs() {
			return this.acrs;
		}

		public void setAcrs(Map<Integer, ACR> acrs) {
			this.acrs = acrs;
		}

		public List<Scope.Value> getSupportedScopes() {
			List<Scope.Value> supportedScopes = new ArrayList<>();
			supportedScopes.addAll(this.openidScopes);
			supportedScopes.addAll(this.resourceScopes.keySet());

			return supportedScopes;
		}

		private static Map<Integer, ACR> defaultAcrs() {
			Map<Integer, ACR> acrs = new HashMap<>();
			acrs.put(1, new ACR("1"));
			return acrs;
		}

	}

	@Validated
	public static class AuthorizationCode {

		/**
		 * Default Authorization Code lifetime, in seconds.
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
		 * Default Access Token lifetime, in seconds.
		 */
		@Range(min = 1, max = 3600)
		private int lifetime = 600;

		/**
		 * JWS algorithm used for signing Access Tokens.
		 */
		private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;

		/**
		 * Comma-separated list of subject claims to be included in Access Tokens.
		 */
		private List<String> subjectClaims = new ArrayList<>();

		public int getLifetime() {
			return this.lifetime;
		}

		public void setLifetime(int lifetime) {
			this.lifetime = lifetime;
		}

		public JWSAlgorithm getJwsAlgorithm() {
			return this.jwsAlgorithm;
		}

		public void setJwsAlgorithm(JWSAlgorithm jwsAlgorithm) {
			this.jwsAlgorithm = jwsAlgorithm;
		}

		public List<String> getSubjectClaims() {
			return this.subjectClaims;
		}

		public void setSubjectClaims(List<String> subjectClaims) {
			this.subjectClaims = subjectClaims;
		}

	}

	@Validated
	public static class RefreshToken {

		/**
		 * Default Refresh Token lifetime, in seconds, zero implies no expiration.
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
	public static class IdToken {

		/**
		 * Default ID Token lifetime, in seconds.
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
	public static class Claim {

		/**
		 * Mappings of scopes to custom claims.
		 */
		private Map<Scope.Value, List<String>> scopeClaims = new HashMap<>();

		public Map<Scope.Value, List<String>> getScopeClaims() {
			return this.scopeClaims;
		}

		public void setScopeClaims(Map<Scope.Value, List<String>> scopeClaims) {
			this.scopeClaims = scopeClaims;
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
