package org.globus.crux.jsse;

public class AbstractNamedSecurityObject implements NamedSecurityObject {

	private String description;
	private String name;

	public String getDescription() {
		return description;
	}

	public String getName() {
		return name;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public void setName(String name) {
		this.name = name;
	}

}
