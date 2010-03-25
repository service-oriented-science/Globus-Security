package org.globus.security.authorization;

import java.util.ArrayList;
import java.util.List;

import org.globus.crux.setup.AbstractComponentFactory;
import org.globus.crux.setup.ComponentMetadata;
import org.globus.crux.setup.ParameterMetadata;

public class PIPInterceptorFactory extends
		AbstractComponentFactory<PIPInterceptor> {

	private ComponentMetadata<PIPInterceptor> metadata;

	public PIPInterceptorFactory() {
		metadata = new ComponentMetadata<PIPInterceptor>();
		metadata.setDescription("This is a dummy PIP");
		metadata.setName("DummyPIP");
		metadata.setType(PIPInterceptor.class);
		List<ParameterMetadata> parameters = new ArrayList<ParameterMetadata>();
		metadata.setParameters(parameters);
	}

	public PIPInterceptor getComponent() {
		return new PIPInterceptor() {

			public NonRequestEntities collectAttributes(
					RequestEntities requestAttr) throws AttributeException {
				// TODO Auto-generated method stub
				return null;
			}

			public void close() throws CloseException {
				// TODO Auto-generated method stub

			}
		};
	}

	public ComponentMetadata<PIPInterceptor> getMetadata() {
		// TODO Auto-generated method stub
		return null;
	}

	public void setParameter(ParameterMetadata<?> paramMeta, Object value) {
		// TODO Auto-generated method stub

	}
}
