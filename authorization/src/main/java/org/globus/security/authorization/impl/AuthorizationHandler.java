package org.globus.security.authorization.impl;

import java.util.List;

import org.globus.security.authorization.AuthorizationEngineSpi;
import org.globus.security.authorization.AuthorizationException;
import org.globus.security.authorization.BootstrapPIP;
import org.globus.security.authorization.Decision;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.RequestEntities;
import org.globus.util.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthorizationHandler {
	List<BootstrapPIP> bootstrapPIPs;
	AuthorizationEngineSpi adminEngine;
	EntityAttributes containerEntity;
	private static I18n i18n = I18n.getI18n(
			"org.globus.wsrf.impl.security.authorization.errors",
			AuthorizationHandler.class.getClassLoader());
	private Logger logger = LoggerFactory.getLogger(getClass());

	public void handle() throws AuthorizationException {
		RequestEntities entities = new RequestEntities();
		for (BootstrapPIP pip : bootstrapPIPs) {
			pip.collectAttributes(entities);
		}
		if (adminEngine != null) {
			checkAdminDecision(entities);
		}
	}

	private boolean checkAdminDecision(RequestEntities request)
			throws AuthorizationException {
		Decision adminDecision = null;

		try {
			adminDecision = adminEngine.engineAuthorize(request,
					containerEntity);
		} catch (AuthorizationException e) {
			// TODO Auto-generated catch block
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
