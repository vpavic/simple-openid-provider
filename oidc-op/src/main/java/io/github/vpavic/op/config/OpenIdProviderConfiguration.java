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
				Collections.singletonList(SubjectType.PUBLIC),
				URI.create(this.properties.getIssuer() + "/oauth2/keys"));
		providerMetadata.setAuthorizationEndpointURI(URI.create(this.properties.getIssuer() + "/oauth2/authorize"));
		providerMetadata.setTokenEndpointURI(URI.create(this.properties.getIssuer() + "/oauth2/token"));
		providerMetadata.setUserInfoEndpointURI(URI.create(this.properties.getIssuer() + "/oauth2/userinfo"));
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

}
