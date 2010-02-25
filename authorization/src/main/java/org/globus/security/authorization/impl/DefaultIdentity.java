package org.globus.security.authorization.impl;

import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;

import org.globus.security.authorization.AttributeIdentifier;
import org.globus.security.authorization.Constants;

public class DefaultIdentity extends Identity {

	private static final long serialVersionUID = 6359760324072498446L;
	private AttributeIdentifier iden = new AttributeIdentifier(Constants.SUBJECT_ATTRIBUTE_ID,
			Constants.SUBJECT_DATATYPE_URI, true);

	public DefaultIdentity(Subject subject, Set<Principal> principals, Identity issuer) {
		super(subject, principals, issuer);
	}

	@Override
	AttributeIdentifier getSubjectIdentifier() {
		return iden;
	}

}
