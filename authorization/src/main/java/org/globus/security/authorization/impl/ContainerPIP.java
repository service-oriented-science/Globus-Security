/*
 * Copyright 1999-2006 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.globus.security.authorization.impl;

import java.util.Calendar;

import javax.inject.Inject;
import javax.xml.namespace.QName;

import org.globus.security.authorization.Attribute;
import org.globus.security.authorization.AttributeException;
import org.globus.security.authorization.BootstrapPIP;
import org.globus.security.authorization.ChainConfig;
import org.globus.security.authorization.CloseException;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.IdentityAttributeCollection;
import org.globus.security.authorization.InitializeException;
import org.globus.security.authorization.NonRequestEntities;
import org.globus.security.authorization.RequestEntities;
import org.globus.security.authorization.util.AttributeUtil;

public class ContainerPIP implements BootstrapPIP {

	@Inject
	private GlobusContext context;

	public void initialize(String chainName, String prefix, ChainConfig config) throws InitializeException {

	}

	public void collectRequestAttributes(RequestEntities requestAttrs) throws AttributeException {

		EntityAttributes containerEntity = context.getContainerEntity();

		/*
		 * Need service endpoint here // service String servicePath =
		 * ContextUtils.getTargetServicePath(this.context); // base URL URL
		 * baseURL = null; try { baseURL = ServiceHost.getBaseURL(this.context);
		 * } catch (IOException ioe) { throw new AttributeException(ioe); }
		 * 
		 * AttributeIdentifier serviceIden =
		 * AttributeUtil.getServiceIdentifier(); // since this is done per
		 * operaiton, the validity can be infinity Attribute serviceAttribute =
		 * new Attribute(serviceIden, containerIssuer, now, null);
		 * serviceAttribute.addAttributeValue(baseURL + servicePath);
		 * IdentityAttributeCollection attrCol = new
		 * IdentityAttributeCollection(); attrCol.add(serviceAttribute);
		 * 
		 * EntityAttributes resourceEntity = requestAttrs.getResource(); if
		 * (resourceEntity == null) { resourceEntity = new
		 * EntityAttributes(attrCol); requestAttrs.setResource(resourceEntity);
		 * } else { resourceEntity.addIdentityAttributes(attrCol); }
		 */

		QName operation = context.getOperation();
		Attribute operationAttribute = new Attribute(AttributeUtil.getOperationAttrIdentifier(), containerEntity,
				Calendar.getInstance(), null);
		operationAttribute.addAttributeValue(operation);
		IdentityAttributeCollection attrCol = new IdentityAttributeCollection();
		attrCol.add(operationAttribute);

		EntityAttributes actionEntity = requestAttrs.getAction();
		if (actionEntity == null) {
			actionEntity = new EntityAttributes(attrCol);
			requestAttrs.setAction(actionEntity);
		} else {
			actionEntity.addIdentityAttributes(attrCol);
		}
	}

	public NonRequestEntities collectAttributes(RequestEntities requestAttr) throws AttributeException {
		return null;
	}

	public void close() throws CloseException {
	}
}
