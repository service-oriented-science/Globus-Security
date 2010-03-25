package org.globus.crux.internal;

import java.io.InputStream;

import org.apache.commons.collections.ExtendedProperties;
import org.apache.velocity.exception.ResourceNotFoundException;
import org.apache.velocity.runtime.resource.Resource;
import org.apache.velocity.runtime.resource.loader.ResourceLoader;

public class GlobusResourceLoader extends ResourceLoader {

	@Override
	public long getLastModified(Resource arg0) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public InputStream getResourceStream(String arg0) throws ResourceNotFoundException {
		return BaseController.class.getClassLoader().getResourceAsStream(arg0);
	}

	@Override
	public void init(ExtendedProperties arg0) {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean isSourceModified(Resource arg0) {
		// TODO Auto-generated method stub
		return false;
	}
}
