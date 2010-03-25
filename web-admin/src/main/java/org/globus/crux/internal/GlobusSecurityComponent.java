package org.globus.crux.internal;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import javax.inject.Qualifier;

@Qualifier
@Target( { TYPE, METHOD, FIELD })
@Retention(RUNTIME)
public @interface GlobusSecurityComponent {
	public enum SecurityObject {
		PIP, BOOTSTRAP_PIP, PDP, AUTHORIZATION_ENGINE
	}

	SecurityObject type();

}
