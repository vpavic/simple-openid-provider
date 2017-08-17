package io.github.vpavic.op.config;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.vpavic.op.client.ClientRepository;
import io.github.vpavic.op.endpoint.AuthorizationEndpoint;
import io.github.vpavic.op.endpoint.CheckSessionEndpoint;
import io.github.vpavic.op.endpoint.KeysEndpoint;
import io.github.vpavic.op.endpoint.TokenEndpoint;
import io.github.vpavic.op.endpoint.UserInfoEndpoint;

@Configuration
@EnableConfigurationProperties(OpenIdProviderProperties.class)
public class OpenIdProviderConfiguration {

	private final OpenIdProviderProperties properties;

	public OpenIdProviderConfiguration(OpenIdProviderProperties properties) {
		this.properties = properties;
	}

	@Bean
	public ClientAuthenticationVerifier<ClientRepository> clientAuthenticationVerifier() {
		return new ClientAuthenticationVerifier<>(new ClientRepositoryClientCredentialsSelector(), null,
				Collections.singleton(new Audience(this.properties.getIssuer())));
	}

	@Bean
	public OIDCProviderMetadata providerMetadata() {
		OIDCProviderMetadata providerMetadata = new OIDCProviderMetadata(new Issuer(this.properties.getIssuer()),
				Collections.singletonList(SubjectType.PUBLIC), createURI(KeysEndpoint.PATH_MAPPING));
		providerMetadata.setAuthorizationEndpointURI(createURI(AuthorizationEndpoint.PATH_MAPPING));
		providerMetadata.setTokenEndpointURI(createURI(TokenEndpoint.PATH_MAPPING));
		providerMetadata.setUserInfoEndpointURI(createURI(UserInfoEndpoint.PATH_MAPPING));
		providerMetadata.setCheckSessionIframeURI(createURI(CheckSessionEndpoint.PATH_MAPPING));
		providerMetadata.setEndSessionEndpointURI(createURI(SecurityConfiguration.LOGOUT_URL));
		providerMetadata.setScopes(new Scope(OIDCScopeValue.OPENID));
		providerMetadata.setResponseTypes(Arrays.asList(new ResponseType(ResponseType.Value.CODE),
				new ResponseType(OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN),
				new ResponseType(OIDCResponseTypeValue.ID_TOKEN),
				new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN),
				new ResponseType(ResponseType.Value.CODE, ResponseType.Value.TOKEN),
				new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN)));
		providerMetadata.setResponseModes(Arrays.asList(ResponseMode.QUERY, ResponseMode.FRAGMENT));
		providerMetadata.setGrantTypes(Collections.singletonList(GrantType.AUTHORIZATION_CODE));
		providerMetadata.setCodeChallengeMethods(Arrays.asList(CodeChallengeMethod.PLAIN, CodeChallengeMethod.S256));
		providerMetadata.setTokenEndpointAuthMethods(Arrays.asList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
				ClientAuthenticationMethod.CLIENT_SECRET_POST));
		providerMetadata.setIDTokenJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
		return providerMetadata;
	}

	private URI createURI(String path) {
		return URI.create(this.properties.getIssuer() + path);
	}

}
