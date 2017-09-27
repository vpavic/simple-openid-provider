package io.github.vpavic.op.config;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.vpavic.op.oauth2.endpoint.AuthorizationEndpoint;
import io.github.vpavic.op.oauth2.endpoint.CheckSessionIframe;
import io.github.vpavic.op.oauth2.endpoint.ClientRegistrationEndpoint;
import io.github.vpavic.op.oauth2.endpoint.EndSessionEndpoint;
import io.github.vpavic.op.oauth2.endpoint.KeysEndpoint;
import io.github.vpavic.op.oauth2.endpoint.RevocationEndpoint;
import io.github.vpavic.op.oauth2.endpoint.TokenEndpoint;
import io.github.vpavic.op.oauth2.endpoint.UserInfoEndpoint;

@Configuration
@EnableConfigurationProperties(OpenIdProviderProperties.class)
public class OpenIdProviderConfiguration {

	private static final Logger logger = LoggerFactory.getLogger(OpenIdProviderConfiguration.class);

	private final OpenIdProviderProperties properties;

	private final ObjectMapper objectMapper;

	public OpenIdProviderConfiguration(OpenIdProviderProperties properties, ObjectProvider<ObjectMapper> objectMapper) {
		this.properties = properties;
		this.objectMapper = objectMapper.getObject();
	}

	@Bean
	public OIDCProviderMetadata providerMetadata() throws Exception {
		OIDCProviderMetadata providerMetadata = new OIDCProviderMetadata(issuer(),
				Collections.singletonList(SubjectType.PUBLIC), createURI(KeysEndpoint.PATH_MAPPING));
		providerMetadata.setAuthorizationEndpointURI(createURI(AuthorizationEndpoint.PATH_MAPPING));
		providerMetadata.setTokenEndpointURI(createURI(TokenEndpoint.PATH_MAPPING));
		providerMetadata.setUserInfoEndpointURI(createURI(UserInfoEndpoint.PATH_MAPPING));
		providerMetadata.setRegistrationEndpointURI(createURI(ClientRegistrationEndpoint.PATH_MAPPING));
		providerMetadata.setRevocationEndpointURI(createURI(RevocationEndpoint.PATH_MAPPING));
		providerMetadata.setCheckSessionIframeURI(checkSessionIframeUri());
		providerMetadata.setEndSessionEndpointURI(endSessionEndpointUri());
		providerMetadata.setScopes(scopes());
		providerMetadata.setResponseTypes(Arrays.asList(new ResponseType(ResponseType.Value.CODE),
				new ResponseType(OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN),
				new ResponseType(OIDCResponseTypeValue.ID_TOKEN),
				new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN),
				new ResponseType(ResponseType.Value.CODE, ResponseType.Value.TOKEN),
				new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN)));
		providerMetadata.setResponseModes(Arrays.asList(ResponseMode.QUERY, ResponseMode.FRAGMENT));
		providerMetadata.setGrantTypes(Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT,
				GrantType.REFRESH_TOKEN, GrantType.PASSWORD, GrantType.CLIENT_CREDENTIALS));
		providerMetadata.setCodeChallengeMethods(Arrays.asList(CodeChallengeMethod.PLAIN, CodeChallengeMethod.S256));
		providerMetadata.setACRs(acrs());
		providerMetadata.setTokenEndpointAuthMethods(Arrays.asList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
				ClientAuthenticationMethod.CLIENT_SECRET_POST, ClientAuthenticationMethod.NONE));
		providerMetadata.setIDTokenJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
		providerMetadata.setClaims(Arrays.asList(IDTokenClaimsSet.ISS_CLAIM_NAME, IDTokenClaimsSet.SUB_CLAIM_NAME,
				IDTokenClaimsSet.AUD_CLAIM_NAME, IDTokenClaimsSet.EXP_CLAIM_NAME, IDTokenClaimsSet.IAT_CLAIM_NAME,
				IDTokenClaimsSet.AUTH_TIME_CLAIM_NAME, IDTokenClaimsSet.NONCE_CLAIM_NAME,
				IDTokenClaimsSet.ACR_CLAIM_NAME, IDTokenClaimsSet.AMR_CLAIM_NAME, IDTokenClaimsSet.AZP_CLAIM_NAME));
		providerMetadata.setSupportsFrontChannelLogout(supportsFrontChannelLogout());
		providerMetadata.setSupportsFrontChannelLogoutSession(supportsFrontChannelLogoutSession());

		logger.info("Initializing OpenID Provider with configuration:\n{}", this.objectMapper
				.writer(SerializationFeature.INDENT_OUTPUT).writeValueAsString(providerMetadata.toJSONObject()));

		return providerMetadata;
	}

	private Issuer issuer() {
		return new Issuer(this.properties.getIssuer());
	}

	private URI createURI(String path) {
		return URI.create(this.properties.getIssuer() + path);
	}

	private URI checkSessionIframeUri() {
		return this.properties.getSessionManagement().isEnabled() ? createURI(CheckSessionIframe.PATH_MAPPING) : null;
	}

	private URI endSessionEndpointUri() {
		return this.properties.isLogoutEnabled() ? createURI(EndSessionEndpoint.PATH_MAPPING) : null;
	}

	private Scope scopes() {
		Scope scope = new Scope();
		for (String openidScope : this.properties.getAuthorization().getOpenidScopes()) {
			scope.add(openidScope);
		}
		for (String resourceScope : this.properties.getAuthorization().getResourceScopes().keySet()) {
			scope.add(resourceScope);
		}
		return scope;
	}

	private List<ACR> acrs() {
		return this.properties.getAuthorization().getAcrs().stream().map(ACR::new).collect(Collectors.toList());
	}

	private boolean supportsFrontChannelLogout() {
		return this.properties.getFrontChannelLogout().isEnabled();
	}

	private boolean supportsFrontChannelLogoutSession() {
		return supportsFrontChannelLogout();
	}

}
