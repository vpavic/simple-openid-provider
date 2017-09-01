package io.github.vpavic.op.config;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;

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
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.vpavic.op.endpoint.AuthorizationEndpoint;
import io.github.vpavic.op.endpoint.CheckSessionIframe;
import io.github.vpavic.op.endpoint.KeysEndpoint;
import io.github.vpavic.op.endpoint.LogoutEndpoint;
import io.github.vpavic.op.endpoint.RevocationEndpoint;
import io.github.vpavic.op.endpoint.TokenEndpoint;
import io.github.vpavic.op.endpoint.UserInfoEndpoint;

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
		OIDCProviderMetadata providerMetadata = new OIDCProviderMetadata(new Issuer(this.properties.getIssuer()),
				Collections.singletonList(SubjectType.PUBLIC), createURI(KeysEndpoint.PATH_MAPPING));
		providerMetadata.setAuthorizationEndpointURI(createURI(AuthorizationEndpoint.PATH_MAPPING));
		providerMetadata.setTokenEndpointURI(createURI(TokenEndpoint.PATH_MAPPING));
		providerMetadata.setUserInfoEndpointURI(createURI(UserInfoEndpoint.PATH_MAPPING));
		providerMetadata.setRevocationEndpointURI(createURI(RevocationEndpoint.PATH_MAPPING));
		providerMetadata.setCheckSessionIframeURI(
				this.properties.isSessionManagementEnabled() ? createURI(CheckSessionIframe.PATH_MAPPING) : null);
		providerMetadata.setEndSessionEndpointURI(this.properties.isSessionManagementOrFrontChannelLogoutEnabled()
				? createURI(LogoutEndpoint.PATH_MAPPING)
				: null);
		providerMetadata.setScopes(new Scope(OIDCScopeValue.OPENID));
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
		providerMetadata.setTokenEndpointAuthMethods(Arrays.asList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
				ClientAuthenticationMethod.CLIENT_SECRET_POST, ClientAuthenticationMethod.NONE));
		providerMetadata.setIDTokenJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
		providerMetadata
				.setClaims(Arrays.asList("iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "azp"));
		providerMetadata.setSupportsFrontChannelLogout(this.properties.isFrontChannelLogoutEnabled());
		providerMetadata.setSupportsFrontChannelLogoutSession(this.properties.isFrontChannelLogoutEnabled());

		logger.info("Initializing OpenID Provider with configuration:\n{}", this.objectMapper
				.writer(SerializationFeature.INDENT_OUTPUT).writeValueAsString(providerMetadata.toJSONObject()));

		return providerMetadata;
	}

	private URI createURI(String path) {
		return URI.create(this.properties.getIssuer() + path);
	}

}
