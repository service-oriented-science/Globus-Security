package org.globus.crux.security.internal;

import java.util.UUID;

public class ContainerIdGenerator {

	public static String generateId(){
		return UUID.randomUUID().toString();
	}
}
