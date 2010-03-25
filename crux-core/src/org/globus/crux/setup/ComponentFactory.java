package org.globus.crux.setup;

public interface ComponentFactory<T> {
	
	ComponentMetadata<T> getMetadata();

	T getComponent();

	void setParameter(ParameterMetadata<?> paramMeta, Object value);

}
