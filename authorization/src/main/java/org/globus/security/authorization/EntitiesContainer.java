package org.globus.security.authorization;

public class EntitiesContainer {

	private RequestEntities requestEntities;

	private NonRequestEntities nonRequestEntities;

	public EntitiesContainer(RequestEntities requestEntities, NonRequestEntities nonRequestEntities) {
		super();
		this.requestEntities = requestEntities;
		this.nonRequestEntities = nonRequestEntities;
	}

	public RequestEntities getRequestEntities() {
		return requestEntities;
	}

	public NonRequestEntities getNonRequestEntities() {
		return nonRequestEntities;
	}

}
