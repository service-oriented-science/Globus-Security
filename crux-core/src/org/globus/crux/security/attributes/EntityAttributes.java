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
package org.globus.crux.security.attributes;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import org.globus.util.I18nUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents an entity, consisting of a collection of identity attributes, non-identity attributes
 * and attributes in native format.
 */
public class EntityAttributes implements Serializable {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1530483508802067768L;

	private static I18nUtil i18n = I18nUtil.getI18n("org.globus.security.authorization.errors",
            EntityAttributes.class.getClassLoader());

    private static Logger logger = LoggerFactory.getLogger(EntityAttributes.class.getName());

    // collection of attributes that are not identity attributes
    private AttributeCollection attrCollection;
    // Attributes in native format
    private Set<Object> nativeAttrCollection;
    // collection of attributes that are identity attributes
    private IdentityAttributeCollection identityAttrCollection;

    /**
     * @param idenAttr   Identity attribute collection
     * @param attr       AttributeBase collection
     * @param nativeAttr Set of attribute in native format
     */
    public EntityAttributes(IdentityAttributeCollection idenAttr, AttributeCollection attr, Set<Object> nativeAttr) {

        if ((idenAttr == null) || (idenAttr.size() <= 0)) {
            String err = i18n.getMessage("idenAttrReq");
            logger.error(err);
            throw new IllegalArgumentException(err);
        }

        this.identityAttrCollection = idenAttr;

        this.attrCollection = attr;

        if (nativeAttr != null) {
            this.nativeAttrCollection = new HashSet<Object>(nativeAttr);
        }
    }

    public EntityAttributes(IdentityAttributeCollection idenAttr, AttributeCollection attr) {
        this(idenAttr, attr, null);
    }

    public EntityAttributes(IdentityAttributeCollection idenAttr) {
        this(idenAttr, null, null);
    }

    /**
     * Adds identity attributes to the exisiting list.
     *
     * @param idenAttr IdentityAttributeCollection
     */
    public void addIdentityAttributes(IdentityAttributeCollection idenAttr) {

        if (idenAttr == null) {
            return;
        }

        this.identityAttrCollection.addAll(idenAttr);
    }

    /**
     * Adds to the existing native attributes set.
     *
     * @param set
     */
    public void addNativeAttributes(Set<Object> set) {

        if (set == null) {
            return;
        }

        if (this.nativeAttrCollection == null) {
            this.nativeAttrCollection = new HashSet<Object>(set);
        } else {
            this.nativeAttrCollection.addAll(set);

        }
    }

    /**
     * Adds non-identity attributes to the exisiting collection.
     * Note: attributes are not merged, only appended to the exisiting list.
     *
     * @param attr
     */
    public void addAttributes(AttributeCollection attr) {

        if (attr == null) {
            return;
        }

        if (this.attrCollection == null) {
            this.attrCollection = attr;
        } else {
            this.attrCollection.addAll(attr);
        }
    }

    /**
     * Returns identity attributes
     *
     * @return
     */
    public IdentityAttributeCollection getIdentityAttributes() {
        return this.identityAttrCollection;
    }

    /**
     * Returns non-identity attributes
     *
     * @return
     */
    public AttributeCollection getAttributes() {
        return this.attrCollection;
    }

    /**
     * Returns native attributes
     *
     * @return
     */
    public Set<Object> getNativeAttributes() {
        return this.nativeAttrCollection;
    }

    /**
     * Returns true if atleast one identity attribute in the identity
     * atribute collection matches.
     *
     * @see AttributeCollection#isSameEntity
     */
    public boolean isSameEntity(EntityAttributes entityAttr) {

        if (entityAttr == null) {
            return false;
        }

        IdentityAttributeCollection idenCollToCheck = entityAttr.getIdentityAttributes();
        return this.identityAttrCollection.isSameEntity(idenCollToCheck);
    }

    /**
     * Merges the two entities. Identity attribute collection,
     * non-identity attribute collection are merged, such that if same
     * attributes exists, values and time stamp are merged. Native
     * attributes are just added to the existing set.
     * <p/>
     * Does not check if it is same entity, use <code>isSameEntity</code>
     *
     * @see #isSameEntity
     */
    public void mergeEntities(EntityAttributes entityAttr) {

        if (entityAttr == null) {
            return;
        }

        IdentityAttributeCollection idenColl = entityAttr.getIdentityAttributes();
        this.identityAttrCollection.addAll(idenColl);

        AttributeCollection attrColl = entityAttr.getAttributes();
        if (attrColl != null) {
            if (this.attrCollection != null) {
                this.attrCollection.addAll(attrColl);
            } else {
                this.attrCollection = attrColl;
            }
        }

        Set<Object> nativeAttrColl = entityAttr.getNativeAttributes();
        if (nativeAttrColl != null) {
            if (this.nativeAttrCollection == null) {
                this.nativeAttrCollection = new HashSet<Object>(nativeAttrColl);
            } else {
                this.nativeAttrCollection.addAll(nativeAttrColl);
            }
        }
    }

    public String toString() {

        StringBuilder str = new StringBuilder("EntityAtributes\n");
        str.append(this.identityAttrCollection.toString());

        if (this.attrCollection != null) {
            str.append(this.attrCollection.toString());
        } else {
            str.append("Non-identity Attributes is null");
        }

        str.append("\nNative AttributeBase is null: ");
        str.append(this.nativeAttrCollection == null);
        str.append("\n");
        return str.toString();
    }
}
