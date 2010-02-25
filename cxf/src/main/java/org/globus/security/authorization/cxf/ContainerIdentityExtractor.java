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

package org.globus.security.authorization.cxf;

import javax.servlet.http.HttpServletRequest;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.globus.security.GlobusTLSContext;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.util.AttributeUtil;

/**
 * Created by IntelliJ IDEA. User: turtlebender Date: Feb 9, 2010 Time: 11:16:44
 * AM To change this template use File | Settings | File Templates.
 */
public class ContainerIdentityExtractor extends AbstractPhaseInterceptor<Message> {

	public ContainerIdentityExtractor() {
		super(Phase.RECEIVE);
	}

	/**
	 * Very simple interceptor that extracts the GlobusSecurityContext from the
	 * HTTP request and puts it into the message Context.
	 * 
	 * @param message The message we are processing.
	 */
	public void handleMessage(Message message) throws Fault {
		GlobusTLSContext sslContext = (GlobusTLSContext) ((HttpServletRequest) message.get("HTTP.REQUEST"))
				.getAttribute(GlobusTLSContext.class.getCanonicalName());
		if (sslContext != null) {
			message.put(GlobusTLSContext.class, sslContext);
		}
		Bus bus = BusFactory.getThreadDefaultBus();
		String containerId = (String) bus.getProperty("GLOBUS_CONTAINER_ID");
		message.put("GLOBUS_CONTAINER_ID", containerId);
		message.put("GLOBUS_SSL_CONTEXT", sslContext);
	}
}
