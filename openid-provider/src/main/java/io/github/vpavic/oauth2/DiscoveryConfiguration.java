package io.github.vpavic.oauth2;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import io.github.vpavic.oauth2.authorization.AuthorizationEndpoint;
import io.github.vpavic.oauth2.checksession.CheckSessionIframe;
import io.github.vpavic.oauth2.client.ClientRegistrationEndpoint;
import io.github.vpavic.oauth2.discovery.DiscoveryEndpoint;
import io.github.vpavic.oauth2.discovery.JwkSetEndpoint;
import io.github.vpavic.oauth2.endsession.EndSessionEndpoint;
import io.github.vpavic.oauth2.jwk.JwkSetLoader;
import io.github.vpavic.oauth2.token.TokenEndpoint;
import io.github.vpavic.oauth2.token.TokenRevocationEndpoint;
import io.github.vpavic.oauth2.userinfo.UserInfoEndpoint;

@Configuration
public class DiscoveryConfiguration {

	private final OpenIdProviderProperties properties;

	private final JwkSetLoader jwkSetLoader;

	public DiscoveryConfiguration(OpenIdProviderProperties properties, ObjectProvider<JwkSetLoader> jwkSetLoader) {
		this.properties = properties;
		this.jwkSetLoader = jwkSetLoader.getObject();
	}

	@Bean
	public OIDCProviderMetadata providerMetadata() {
		OIDCProviderMetadata providerMetadata = new OIDCProviderMetadata(issuer(), subjectTypes(), jwkSetUri());
		providerMetadata.setAuthorizationEndpointURI(authorizationEndpoint());
		providerMetadata.setTokenEndpointURI(tokenEndpoint());
		providerMetadata.setUserInfoEndpointURI(userInfoEndpoint());
		providerMetadata.setRegistrationEndpointURI(registrationEndpoint());
		providerMetadata.setRevocationEndpointURI(revocationEndpoint());
		providerMetadata.setCheckSessionIframeURI(checkSessionIframe());
		providerMetadata.setEndSessionEndpointURI(endSessionEndpoint());
		providerMetadata.setScopes(scope());
		providerMetadata.setResponseTypes(responseTypes());
		providerMetadata.setResponseModes(responseModes());
		providerMetadata.setGrantTypes(grantTypes());
		providerMetadata.setCodeChallengeMethods(codeChallengeMethods());
		providerMetadata.setACRs(acrs());
		providerMetadata.setTokenEndpointAuthMethods(tokenEndpointAuthMethods());
		providerMetadata.setIDTokenJWSAlgs(idTokenJwsAlgorithms());
		providerMetadata.setDisplays(displays());
		providerMetadata.setClaimTypes(claimTypes());
		providerMetadata.setClaims(claims());
		providerMetadata.setClaimLocales(claimLocales());
		providerMetadata.setUILocales(uiLocales());
		providerMetadata.setSupportsFrontChannelLogout(supportsFrontChannelLogout());
		providerMetadata.setSupportsFrontChannelLogoutSession(supportsFrontChannelLogoutSession());

		return providerMetadata;
	}

	@Bean
	public DiscoveryEndpoint discoveryEndpoint() {
		return new DiscoveryEndpoint(providerMetadata());
	}

	@Bean
	public JwkSetEndpoint jwkSetEndpoint() {
		return new JwkSetEndpoint(this.jwkSetLoader);
	}

	private Issuer issuer() {
		return new Issuer(this.properties.getIssuer());
	}

	private List<SubjectType> subjectTypes() {
		return Collections.singletonList(SubjectType.PUBLIC);
	}

	private URI createUri(String path) {
		return URI.create(this.properties.getIssuer() + path);
	}

	private URI jwkSetUri() {
		return createUri(JwkSetEndpoint.PATH_MAPPING);
	}

	private URI authorizationEndpoint() {
		return createUri(AuthorizationEndpoint.PATH_MAPPING);
	}

	private URI tokenEndpoint() {
		return createUri(TokenEndpoint.PATH_MAPPING);
	}

	private URI userInfoEndpoint() {
		return createUri(UserInfoEndpoint.PATH_MAPPING);
	}

	private URI registrationEndpoint() {
		return createUri(ClientRegistrationEndpoint.PATH_MAPPING);
	}

	private URI revocationEndpoint() {
		return createUri(TokenRevocationEndpoint.PATH_MAPPING);
	}

	private URI checkSessionIframe() {
		return this.properties.getSessionManagement().isEnabled() ? createUri(CheckSessionIframe.PATH_MAPPING) : null;
	}

	private URI endSessionEndpoint() {
		return (this.properties.getSessionManagement().isEnabled()
				|| this.properties.getFrontChannelLogout().isEnabled()) ? createUri(EndSessionEndpoint.PATH_MAPPING)
						: null;
	}

	private Scope scope() {
		return this.properties.getAuthorization().getSupportedScope();
	}

	private List<ResponseType> responseTypes() {
		return Arrays.asList(new ResponseType(ResponseType.Value.CODE),
				new ResponseType(OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN),
				new ResponseType(OIDCResponseTypeValue.ID_TOKEN),
				new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN),
				new ResponseType(ResponseType.Value.CODE, ResponseType.Value.TOKEN),
				new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN));
	}

	private List<ResponseMode> responseModes() {
		return Arrays.asList(ResponseMode.QUERY, ResponseMode.FRAGMENT, ResponseMode.FORM_POST);
	}

	private List<GrantType> grantTypes() {
		return Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT, GrantType.REFRESH_TOKEN,
				GrantType.PASSWORD, GrantType.CLIENT_CREDENTIALS);
	}

	private List<CodeChallengeMethod> codeChallengeMethods() {
		return Arrays.asList(CodeChallengeMethod.PLAIN, CodeChallengeMethod.S256);
	}

	private List<ACR> acrs() {
		return this.properties.getAuthorization().getAcrs();
	}

	private List<ClientAuthenticationMethod> tokenEndpointAuthMethods() {
		return Arrays.asList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
				ClientAuthenticationMethod.CLIENT_SECRET_POST, ClientAuthenticationMethod.NONE);
	}

	private List<JWSAlgorithm> idTokenJwsAlgorithms() {
		return Arrays.asList(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512, JWSAlgorithm.RS256,
				JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512,
				JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512);
	}

	private List<Display> displays() {
		return Arrays.asList(Display.PAGE, Display.POPUP, Display.TOUCH);
	}

	private List<ClaimType> claimTypes() {
		return Collections.singletonList(ClaimType.NORMAL);
	}

	private List<String> claims() {
		return Arrays.asList(IDTokenClaimsSet.ISS_CLAIM_NAME, IDTokenClaimsSet.SUB_CLAIM_NAME,
				IDTokenClaimsSet.AUD_CLAIM_NAME, IDTokenClaimsSet.EXP_CLAIM_NAME, IDTokenClaimsSet.IAT_CLAIM_NAME,
				IDTokenClaimsSet.AUTH_TIME_CLAIM_NAME, IDTokenClaimsSet.NONCE_CLAIM_NAME,
				IDTokenClaimsSet.ACR_CLAIM_NAME, IDTokenClaimsSet.AMR_CLAIM_NAME, IDTokenClaimsSet.AZP_CLAIM_NAME);
	}

	private List<LangTag> claimLocales() {
		try {
			return Collections.singletonList(new LangTag("en"));
		}
		catch (LangTagException e) {
			throw new RuntimeException(e);
		}
	}

	private List<LangTag> uiLocales() {
		try {
			return Collections.singletonList(new LangTag("en"));
		}
		catch (LangTagException e) {
			throw new RuntimeException(e);
		}
	}

	private boolean supportsFrontChannelLogout() {
		return this.properties.getFrontChannelLogout().isEnabled();
	}

	private boolean supportsFrontChannelLogoutSession() {
		return supportsFrontChannelLogout();
	}

	@Order(-4)
	@Configuration
	public static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatchers()
					.antMatchers(HttpMethod.GET, DiscoveryEndpoint.PATH_MAPPING, JwkSetEndpoint.PATH_MAPPING)
					.and()
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			// @formatter:on
		}

	}

}
