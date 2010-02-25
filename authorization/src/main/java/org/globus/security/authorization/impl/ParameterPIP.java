/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.globus.security.authorization.impl;

import javax.inject.Inject;

import org.globus.security.authorization.AttributeException;
import org.globus.security.authorization.BootstrapPIP;
import org.globus.security.authorization.CloseException;
import org.globus.security.authorization.NonRequestEntities;
import org.globus.security.authorization.RequestEntities;

/**
 * Created by IntelliJ IDEA. User: turtlebender Date: Jan 27, 2010 Time:
 * 10:40:08 AM To change this template use File | Settings | File Templates.
 */
public class ParameterPIP implements BootstrapPIP {
	
	@Inject private GlobusContext context;

	private static final long serialVersionUID = -5886406584415537083L;

	// private Logger logger = LoggerFactory.getLogger(getClass());
	
	public void close() throws CloseException {
		// To change body of implemented methods use File | Settings | File
		// Templates.
	}

	/**
	 * Collect attributes about entities of interest. If the attribute is about
	 * the requested subject, resource or action, it should be added to the
	 * RequestEntities object. All other attributes should be returned as
	 * NonRequestEntities. Attributes about same entities, should be merged as a
	 * single EntityAttribute object.
	 */
	public NonRequestEntities collectAttributes(RequestEntities requestAttr) throws AttributeException {
		context.get(String.class);
		return null; // To change body of implemented methods use File |
						// Settings | File Templates.
	}
	
	

	public void collectRequestAttributes(RequestEntities requestAttrs) throws AttributeException {
		DefaultIdentity container = new DefaultIdentity(context.getContainerSubject(), context.getContainerSubject().getPrincipals(), null);
		PeerIdentity peer = new PeerIdentity(context.getPeerSubject(), context.getPeerSubject().getPrincipals(), container);
		// GlobusContext context =
		// AttributeUtil.getGlobusContext(requestAttrs.getEnvironment().getAttributes());
		// EntityAttributes containerAttributes =
		// AttributeUtil.getContainerEntity((String)
		// context.get("GLOBUS_CONTAINER_ID"),
		// context.get(GlobusTLSContext.class));

	}
}
