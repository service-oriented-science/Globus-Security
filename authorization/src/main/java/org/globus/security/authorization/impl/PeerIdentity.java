package org.globus.security.authorization.impl;

import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;

import org.globus.security.authorization.AttributeIdentifier;
import org.globus.security.authorization.Constants;

public class PeerIdentity extends Identity {

	private static final long serialVersionUID = 3714179417944135512L;

	public static AttributeIdentifier PEER_SUBJECT_IDENTIFIER = new AttributeIdentifier(Constants.SUBJECT_ATTRIBUTE_ID,
			Constants.SUBJECT_DATATYPE_URI, true);

	public PeerIdentity(Subject subject, Set<Principal> principals, Identity issuer) {
		super(subject, principals, issuer);
	}

	@Override
	AttributeIdentifier getSubjectIdentifier() {
		return PeerIdentity.PEER_SUBJECT_IDENTIFIER;
	}

}
