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
package org.globus.security.authorization.util;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;

import org.globus.security.authorization.Attribute;
import org.globus.security.authorization.AttributeCollection;
import org.globus.security.authorization.AttributeIdentifier;
import org.globus.security.authorization.Constants;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.IdentityAttributeCollection;

/**
 * Fill Me
 */
@SuppressWarnings("unchecked")
public final class AttributeUtil {

	public static AttributeIdentifier getEnvironmentContextAttrIdentifier() {
		return new AttributeIdentifier(Constants.ENVIRONMENT_ATTRIBUTE_URI, Constants.ENVIRONMENT_DATATYPE_URI, true);
	}

	public static AttributeIdentifier getPeerSubjectAttrIdentifier() {
		return new AttributeIdentifier(Constants.SUBJECT_ATTRIBUTE_ID, Constants.SUBJECT_DATATYPE_URI, true);
	}

	public static AttributeIdentifier getPrincipalIdentifier() {
		return new AttributeIdentifier(Constants.PRINCIPAL_ATTRIBUTE_ID, Constants.PRINCIPAL_DATATYPE_URI, true);
	}

	public static <T> Collection<T> getAttributeValue(AttributeCollection collection, AttributeIdentifier attrIden,
			EntityAttributes issuer, Class<T> type) {
		Map<EntityAttributes, ?> attrMap = collection.getAttributeMap(attrIden);
		Attribute<T> attribute = null;
		// TODO: this probably needs to be the actual container issuer entity,
		// but for now.
		if (issuer == null) {
			if (attrMap.size() == 1) {
				attribute = (Attribute<T>) attrMap.values().iterator().next();
			}
		} else {
			attribute = (Attribute<T>) attrMap.get(issuer);
		}
		return attribute == null ? null : attribute.getAttributeValueSet();
	}

	public static EntityAttributes getContainerEntity(String containerId, Subject subject) {
		IdentityAttributeCollection attrCol = new IdentityAttributeCollection();
		attrCol.add(getContainerIdAttribute(containerId, null));
		if (subject != null) {
			attrCol.add(AttributeUtil.getContainerPrincipalAttribute(subject, null));
			attrCol.add(getContainerSubjectAttribute(subject, null));
		}
		EntityAttributes containerEntityIssuer = new EntityAttributes(attrCol);
		attrCol = new IdentityAttributeCollection();
        attrCol.add(getContainerIdAttribute(containerId, containerEntityIssuer));
		if (subject != null) {
			attrCol.add(AttributeUtil.getContainerPrincipalAttribute(subject, containerEntityIssuer));
			attrCol.add(getContainerSubjectAttribute(subject, containerEntityIssuer));
		}
        return new EntityAttributes(attrCol);
	}

	private static Attribute getContainerIdAttribute(String containerId, EntityAttributes issuer) {
		Calendar now = Calendar.getInstance();
		// FIXME: issuer is null here
		AttributeIdentifier containerIden = new AttributeIdentifier(Constants.CONTAINER_ATTRIBUTE_URI,
				Constants.STRING_DATATYPE_URI, true);
		// issuer is null
		Attribute containerAttribute = new Attribute(containerIden, issuer, now, null);

		containerAttribute.addAttributeValue(containerId);
		return containerAttribute;
	}

	private static Attribute getContainerSubjectAttribute(Subject subject, EntityAttributes issuer) {
		AttributeIdentifier iden = new AttributeIdentifier(Constants.SUBJECT_ATTRIBUTE_ID,
				Constants.SUBJECT_DATATYPE_URI, true);
		// issuer is null
		Attribute containerAttribute = new Attribute(iden, issuer, Calendar.getInstance(), null);
		containerAttribute.addAttributeValue(subject);
		return containerAttribute;
	}

	private static Attribute getContainerPrincipalAttribute(Subject subject, EntityAttributes issuer) {
		Set<X509Certificate[]> certChain = subject.getPublicCredentials(X509Certificate[].class);
		Calendar[] validity = getValidity(certChain.iterator().next());
		AttributeIdentifier attrIden = AttributeUtil.getPrincipalIdentifier();
		Attribute principalAttr = new Attribute(attrIden, issuer, validity[1], validity[0]);
		Set principals = subject.getPrincipals();
		principalAttr.setAttributeValueSet(principals);
		return principalAttr;
	}

	public static Calendar[] getValidity(X509Certificate[] certArray) {

		if ((certArray == null) || (certArray.length < 1)) {
			return null;
		}
		Date notAfter = certArray[0].getNotAfter();
		Date notBefore = certArray[0].getNotBefore();
		for (int i = 1; i < certArray.length; i++) {
			Date notAfteri = certArray[i].getNotAfter();
			if (notAfteri.before(notAfter)) {
				notAfter = notAfteri;
			}
			Date notBeforei = certArray[i].getNotBefore();
			if (notBeforei.after(notBefore)) {
				notBefore = notBeforei;
			}
		}

		Calendar validTill = Calendar.getInstance();
		validTill.setTime(notAfter);
		Calendar validFrom = Calendar.getInstance();
		validFrom.setTime(notBefore);

		return new Calendar[] { validTill, validFrom };
	}

	public static IdentityAttributeCollection createRequestor(Subject subject, EntityAttributes issuer) {
		Calendar now = Calendar.getInstance();
		IdentityAttributeCollection identAttrColl = new IdentityAttributeCollection();
		Attribute<Object> subjectAttribute = new Attribute<Object>(getPrincipalIdentifier(), issuer, now, null);
		identAttrColl.add(subjectAttribute);
		Set<Principal> principals = subject.getPrincipals();
		AttributeIdentifier identifier = AttributeUtil.getPrincipalIdentifier();
		Attribute<Principal> principalAttribute = new Attribute<Principal>(identifier, issuer, now, null);
		principalAttribute.setAttributeValueSet(principals);
		identAttrColl.add(principalAttribute);
		return identAttrColl;
	}

//	public static GlobusContext getGlobusContext(AttributeCollection collection) {
//		Collection<GlobusContext> contextCollection = getAttributeValue(collection,
//				getEnvironmentContextAttrIdentifier(), null, GlobusContext.class);
//		if (!contextCollection.isEmpty()) {
//			return contextCollection.iterator().next();
//		}
//		return null;
//	}

	// public static AttributeBase

	private AttributeUtil() {
		// this should not be initialized.
	}

	/**
	 * Fill Me
	 * 
	 * @param attributeList
	 *            Fill Me
	 * @param entityAttr
	 *            Fill Me
	 * @return Fill Me
	 */
	public static EntityAttributes getMatchedEntity(List attributeList, EntityAttributes entityAttr) {

		if ((attributeList == null) || (entityAttr == null)) {
			return null;
		}

		for (Object anAttributeList : attributeList) {
			EntityAttributes retAttr = (EntityAttributes) anAttributeList;
			if (retAttr.isSameEntity(entityAttr)) {
				return retAttr;
			}
		}
		return null;
	}
}
