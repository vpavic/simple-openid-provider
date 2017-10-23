package io.github.vpavic.oauth2;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;

/**
 * OpenID Provider configuration.
 *
 * @author Vedran Pavic
 */
@Configuration
@EnableConfigurationProperties(OpenIdProviderProperties.class)
public class OpenIdProviderConfiguration {

	@Bean
	@ConfigurationPropertiesBinding
	public StringToAcrConverter stringToAcrConverter() {
		return new StringToAcrConverter();
	}

	@Bean
	@ConfigurationPropertiesBinding
	public StringToBearerAccessTokenConverter stringToBearerAccessTokenConverter() {
		return new StringToBearerAccessTokenConverter();
	}

	@Bean
	@ConfigurationPropertiesBinding
	public StringToIssuerConverter stringToIssuerConverter() {
		return new StringToIssuerConverter();
	}

	@Bean
	@ConfigurationPropertiesBinding
	public StringToScopeValueConverter stringToScopeValueConverter() {
		return new StringToScopeValueConverter();
	}

	private static class StringToAcrConverter implements Converter<String, ACR> {

		@Override
		public ACR convert(String source) {
			return new ACR(source);
		}

	}

	private static class StringToBearerAccessTokenConverter implements Converter<String, BearerAccessToken> {

		@Override
		public BearerAccessToken convert(String source) {
			return new BearerAccessToken(source);
		}

	}

	private static class StringToIssuerConverter implements Converter<String, Issuer> {

		@Override
		public Issuer convert(String source) {
			return new Issuer(source);
		}

	}

	private static class StringToScopeValueConverter implements Converter<String, Scope.Value> {

		@Override
		public Scope.Value convert(String source) {
			return new Scope.Value(source);
		}

	}

}
