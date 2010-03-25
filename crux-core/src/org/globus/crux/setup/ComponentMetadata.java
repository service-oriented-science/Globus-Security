package org.globus.crux.setup;

import java.util.Collection;

public class ComponentMetadata<T> {
	private Class<T> type;
	private Collection<ParameterMetadata> parameters;
	private String description;
	private String name;

	public Class<T> getType() {
		return type;
	}

	public void setType(Class<T> type) {
		this.type = type;
	}

	public Collection<ParameterMetadata> getParameters() {
		return parameters;
	}

	public void setParameters(Collection<ParameterMetadata> parameters) {
		this.parameters = parameters;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}
