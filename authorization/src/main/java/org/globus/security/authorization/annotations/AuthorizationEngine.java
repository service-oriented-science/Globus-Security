package org.globus.security.authorization.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface AuthorizationEngine {

	String pid();

	String name();

	String description() default "";

	String author() default "";

	String date() default "";

	String documentationPath() default "";
}
