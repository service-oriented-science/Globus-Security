package org.globus.security.authorization.impl;

import java.security.Principal;
import java.util.Calendar;
import java.util.Set;

import javax.security.auth.Subject;

import org.globus.security.authorization.Attribute;
import org.globus.security.authorization.AttributeIdentifier;
import org.globus.security.authorization.Constants;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.IdentityAttributeCollection;
import org.globus.security.authorization.util.AttributeUtil;

public abstract class Identity extends EntityAttributes {

	private static final long serialVersionUID = -4421838197894674068L;
	
	protected static AttributeIdentifier PRINCIPAL_IDENTIFIER = 
		new AttributeIdentifier(Constants.PRINCIPAL_ATTRIBUTE_ID, Constants.PRINCIPAL_DATATYPE_URI, true);

	private Subject subject;
	private Set<Principal> principals;
	private Identity issuer;

	public Identity(Subject subject, Set<Principal> principals, Identity issuer) {
		super(new IdentityAttributeCollection());
		Calendar now = Calendar.getInstance();
		this.subject = subject;
		this.principals = principals;
		this.issuer = issuer;
		Attribute<Subject> subjectAttr = new Attribute<Subject>(getSubjectIdentifier(), issuer, now, null);
		subjectAttr.addAttributeValue(subject);
		getIdentityAttributes().add(subjectAttr);
		Attribute<Principal> principalAttr = new Attribute<Principal>(AttributeUtil.getPrincipalIdentifier(), issuer,
				now, null, principals);
		getIdentityAttributes().add(principalAttr);
	}

	public Subject getSubject() {
		return subject;
	}

	public Set<Principal> getPrincipals() {
		return principals;
	}

	public Identity getIssuer() {
		return issuer;
	}

	abstract AttributeIdentifier getSubjectIdentifier();

}
