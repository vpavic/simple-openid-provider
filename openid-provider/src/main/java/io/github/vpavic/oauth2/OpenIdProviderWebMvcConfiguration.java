package io.github.vpavic.oauth2;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.MethodParameter;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.converter.Converter;
import org.springframework.format.support.DefaultFormattingConversionService;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class OpenIdProviderWebMvcConfiguration implements WebMvcConfigurer {

	@Bean
	public ConversionService conversionService() {
		DefaultFormattingConversionService conversionService = new DefaultFormattingConversionService();
		conversionService.addConverter(new StringToAcrConverter());
		conversionService.addConverter(new StringToBearerAccessTokenConverter());
		conversionService.addConverter(new StringToClientIdConverter());
		conversionService.addConverter(new StringToIssuerConverter());
		conversionService.addConverter(new StringToJwsAlgorithmConverter());
		conversionService.addConverter(new StringToScopeValueConverter());
		return conversionService;
	}

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
		resolvers.add(new HttpRequestArgumentResolver());
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

	private static class StringToClientIdConverter implements Converter<String, ClientID> {

		@Override
		public ClientID convert(String source) {
			return new ClientID(source);
		}

	}

	private static class StringToIssuerConverter implements Converter<String, Issuer> {

		@Override
		public Issuer convert(String source) {
			return new Issuer(source);
		}

	}

	private static class StringToJwsAlgorithmConverter implements Converter<String, JWSAlgorithm> {

		@Override
		public JWSAlgorithm convert(String source) {
			return JWSAlgorithm.parse(source);
		}

	}

	private static class StringToScopeValueConverter implements Converter<String, Scope.Value> {

		@Override
		public Scope.Value convert(String source) {
			return new Scope.Value(source);
		}

	}

	private static class HttpRequestArgumentResolver implements HandlerMethodArgumentResolver {

		@Override
		public boolean supportsParameter(MethodParameter parameter) {
			return HTTPRequest.class.equals(parameter.getParameterType());
		}

		@Override
		public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
				NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
			return ServletUtils.createHTTPRequest((HttpServletRequest) webRequest.getNativeRequest());
		}

	}

}
