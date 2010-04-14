package org.globus.security.authorization.impl;

import java.util.List;

import javax.security.auth.Subject;
import javax.xml.namespace.QName;

import org.globus.security.authorization.AuthorizationEngineSpi;
import org.globus.security.authorization.AuthorizationException;
import org.globus.security.authorization.BootstrapPIP;
import org.globus.security.authorization.Decision;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.GlobusContext;
import org.globus.security.authorization.RequestEntities;
import org.globus.util.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthorizationHandler {
	private static I18n i18n = I18n.getI18n("org.globus.wsrf.impl.security.authorization.errors",
			AuthorizationHandler.class.getClassLoader());

	private List<BootstrapPIP> bootstrapPIPs;
	private AuthorizationEngineSpi adminEngine;
	private AuthorizationEngineSpi serviceEngine;
	private EntityAttributes containerEntity;

	private Logger logger = LoggerFactory.getLogger(getClass());

	public void handle(GlobusContext context) throws AuthorizationException {

		Subject subject = context.get("peer_subject", Subject.class);
		if (subject == null) {
			logger.debug("No authenticaiton done, so no authz");
			return;
		}

		String servicePath = context.get("service_path", String.class);
		// If null will fail further along chain, so return.
		if (servicePath == null) {
			return;
		}

		boolean authzReq = context.get("authz_required", Boolean.class);
		if (!authzReq) {
			logger.debug("Authz not required, since authentication is not " + " enforced");
			return;
		}

		String opName = null;
		try {
			QName opQName = context.get("operation_name", QName.class);
			opName = opQName.toString();
		} catch (SecurityException exp) {
			// quiet catch
		}

		String dn = context.get("caller_dn", String.class);

		logger.info("operation: {}|path: {}|caller{}", new Object[] { opName, servicePath, dn });

		RequestEntities entities = new RequestEntities();
		for (BootstrapPIP pip : bootstrapPIPs) {
			pip.collectAttributes(entities, context);
		}

		if (adminEngine != null) {
			checkAdminDecision(entities, context);
		}

		if (serviceEngine != null) {
			checkServiceDecision(entities, context);
		}
	}

	private boolean checkServiceDecision(RequestEntities request, GlobusContext context) throws AuthorizationException {
		Decision serviceDecision = null;
		try {
			serviceDecision = serviceEngine.engineAuthorize(request, containerEntity, context);
		} catch (AuthorizationException e) {
			String error = i18n.getMessage("authzFail");
			logger.error(error, e);
			return false;
		}
		if (serviceDecision.isPermit()) {
			return true;
		} else {
			throw new AuthorizationException("authorization failed");
		}
	}

	private boolean checkAdminDecision(RequestEntities request, GlobusContext context) throws AuthorizationException {
		Decision adminDecision = null;
		try {
			adminDecision = adminEngine.engineAuthorize(request, containerEntity, context);
		} catch (AuthorizationException e) {
			String error = i18n.getMessage("authzFail");
			logger.error(error, e);
			return false;
		}
		if (adminDecision.isPermit()) {
			return true;
		} else {
			throw new AuthorizationException("authorization failed");
		}

	}
}
