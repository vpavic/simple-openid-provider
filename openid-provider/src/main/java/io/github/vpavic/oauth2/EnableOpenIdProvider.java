package io.github.vpavic.oauth2;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

/**
 * Convenience annotation for enabling OpenID Provider capabilities.
 *
 * @see OpenIdProviderConfiguration
 * @see OpenIdProviderProperties
 *
 * @author Vedran Pavic
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import(OpenIdProviderConfiguration.class)
public @interface EnableOpenIdProvider {

}
