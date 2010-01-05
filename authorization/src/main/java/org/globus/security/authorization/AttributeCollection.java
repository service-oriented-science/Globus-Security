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
package org.globus.security.authorization;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * Stores a collection of attributes as Map. It maps
 * AttributeIdentifier->"Map of attributes". Each "Map  of attributes" is
 * keyed on the issuer entity attributes with the attribute as the value.
 * Note that the EntityAttribute class does not override the equals method to
 * contain the semantic equal functionality, where entity attributes are equal
 * if atleast one identity attribute is equal. So the method
 * <code>EntityAttribute#isSameEntity<code> should
 * be used to compare EntityAttributes.
 */
public class AttributeCollection implements Serializable {

    private static Logger logger =
            LoggerFactory.getLogger(AttributeCollection.class.getName());

    private Map map;

    public AttributeCollection() {
        this.map = Collections.synchronizedMap(new HashMap());
    }

    /**
     * Adds an attribute to the collection. If attribute already
     * exists, the values are merged.
     */
    public void add(Attribute attribute) {

        if (attribute == null) {
            return;
        }

        AttributeIdentifier iden = attribute.getAttributeIdentifier();

        logger.trace("Adding attribute " + iden.toString());

        // check if this attribute already exists
        HashMap storedMap = (HashMap) this.map.get(iden);

        // if map is null, no attributes with this identity exists.
        // Alternatively it might be a map value of null, but then overwrite is
        // okay, since merge is meaningless.
        if (storedMap == null) {
            logger.trace("No attribute present " + iden.getAttributeId());
            HashMap attrMap = new HashMap();
            attrMap.put(attribute.getIssuer(), attribute);
            this.map.put(iden, attrMap);
        } else {
            logger.trace("see if attribute can be merged " + iden.getAttributeId());
            // Get attribute issuer to see if attribute can be merged
            EntityAttributes newAttrIssuer = attribute.getIssuer();
            // All attributes with null issuer are
            // treated as issued by same entity and hence can be merged
            if (newAttrIssuer == null) {
                // check if hashmap has null as key
                Attribute attr = (Attribute) storedMap.get(null);
                if (attr != null) {
                    logger.trace("null issuer, merge");
                    attr.merge(attribute);
                } else {
                    logger.trace("null issuer, no merge");
                    storedMap.put(newAttrIssuer, attribute);
                }
            } else {
                Iterator issuerKeySet = storedMap.keySet().iterator();
                while (issuerKeySet.hasNext()) {
                    EntityAttributes storedIssuer =
                            (EntityAttributes) issuerKeySet.next();
                    logger.trace("check if issuer is same entity");
                    if (newAttrIssuer.isSameEntity(storedIssuer)) {
                        // merge
                        Attribute attr =
                                (Attribute) storedMap.get(storedIssuer);
                        attr.merge(attribute);
                        return;
                    }
                }
                logger.trace("adding a new entry");
                // no matches found. add a new entry.
                storedMap.put(newAttrIssuer, attribute);
            }
        }
    }


    /**
     * Adds all attributes from the collection.
     */
    public void addAll(AttributeCollection attrCollection) {

        if (attrCollection == null) {
            return;
        }

        Iterator entrySetIterator = attrCollection.getAttributes().iterator();
        while (entrySetIterator.hasNext()) {
            add((Attribute) entrySetIterator.next());
        }
    }

    /**
     * Returns a collection of all attributes in the collection.
     */
    public Collection getAttributes() {
        Collection coll = this.map.values();
        Vector vector = new Vector();
        Iterator it = coll.iterator();
        while (it.hasNext()) {
            HashMap attrMap = (HashMap) it.next();
            vector.addAll(attrMap.values());
        }
        return vector;
    }

    /**
     * Returns all attribute identifiers in the collection
     */
    public Set getAttributeIdentifiers() {
        return this.map.keySet();
    }

    /**
     * Returns all attributes with the given AttributeIdenitfier. The
     * attributes may not have same issuer.
     */
    public Collection getAttributes(AttributeIdentifier identifier) {
        HashMap attrMap = getAttributeMap(identifier);
        if (attrMap != null) {
            return attrMap.values();
        } else {
            return null;
        }
    }

    /**
     * Returns the attribute with said AttributeIdentifier and issuer
     */
    public Attribute getAttribute(AttributeIdentifier identifier,
                                  EntityAttributes issuer) {
        HashMap attrMap = getAttributeMap(identifier);
        if (attrMap == null) {
            return null;
        } else {
            return (Attribute) attrMap.get(issuer);
        }
    }

    /**
     * Returns the HashMap keyed on issuer of attribute, with
     * attribute as value, for the given AttributeIdentifier.
     */
    public HashMap getAttributeMap(AttributeIdentifier identifier) {
        return (HashMap) this.map.get(identifier);
    }

    /**
     * Returns the number of attributes in the collection.
     */
    public int size() {
        Collection entries = this.map.values();
        Iterator iterator = entries.iterator();
        int size = 0;
        while (iterator.hasNext()) {
            HashMap hashMap = (HashMap) iterator.next();
            size = size + hashMap.size();
        }
        return size;
    }

    /**
     * Determines if the attribute collection is same entity. This
     * returns true if atleast one attribute in both collections are equal:
     * same attribute identifier,  same issuer and atlease one value should
     * match. Note that all attributes with issuer as null are
     * treated as issued by same entity.
     */
    public boolean isSameEntity(AttributeCollection collection) {

        if (collection == null) {
            logger.trace("Attribute collection is null");
            return false;
        }

        // if both collections have no attributes, return true
        Set attrIdenSet = collection.getAttributeIdentifiers();
        if ((attrIdenSet.size() == 0) &&
                (this.getAttributeIdentifiers().size() == 0)) {
            return true;
        }

        // get list of identitfiers
        Iterator attrIdenToCheck = attrIdenSet.iterator();

        while (attrIdenToCheck.hasNext()) {

            // get each idetifier
            AttributeIdentifier idenToCheck =
                    (AttributeIdentifier) attrIdenToCheck.next();

            // check if idenifier is in this collection. Since attribute
            // identifier defines equals and hashcode, this can be checked.
            if (!this.map.containsKey(idenToCheck)) {
                continue;
            }

            HashMap attrMap = collection.getAttributeMap(idenToCheck);
            if (attrMap == null) {
                HashMap thisAttrMap = this.getAttributeMap(idenToCheck);
                if (thisAttrMap == null) {
                    return true;
                }

                continue;
            }


            HashMap thisAttrMap = this.getAttributeMap(idenToCheck);

            // for each isssuer, get attribute and see if it matches
            Iterator attrIssuers = attrMap.keySet().iterator();

            while (attrIssuers.hasNext()) {

                EntityAttributes issuerToCompare =
                        (EntityAttributes) attrIssuers.next();

                // if it is null, check if it is in the other collection
                if (issuerToCompare == null) {
                    if (thisAttrMap.containsKey(null)) {
                        // check if attribute value matches
                        Attribute thisAttr =
                                (Attribute) thisAttrMap.get(null);
                        Attribute colAttr =
                                (Attribute) attrMap.get(issuerToCompare);
                        if (colAttr == null) {
                            if (thisAttr == null) {
                                return true;
                            }
                            continue;
                        } else {
                            if (colAttr.valueMatches(thisAttr)) {
                                return true;
                            }
                            continue;
                        }
                    }
                    continue;
                }

                Iterator thisIssuers = thisAttrMap.keySet().iterator();
                while (thisIssuers.hasNext()) {
                    EntityAttributes thisIssuerToCompare =
                            (EntityAttributes) thisIssuers.next();
                    if (issuerToCompare.isSameEntity(thisIssuerToCompare)) {
                        // check if atleast one value is present
                        Attribute thisAttr = (Attribute) thisAttrMap
                                .get(thisIssuerToCompare);
                        Attribute colAttr =
                                (Attribute) attrMap.get(issuerToCompare);
                        if (thisAttr == null) {
                            if (colAttr == null) {
                                return true;
                            }
                            continue;
                        }
                        if (thisAttr.valueMatches(colAttr)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    protected String getDescription() {
        return "Non-identity Attribute Collection";
    }

    public String toString() {

        StringBuffer str = new StringBuffer(getDescription() + "\n");
        Collection attributes = getAttributes();
        if (attributes != null) {
            Iterator iterator = attributes.iterator();
            while (iterator.hasNext()) {
                str.append(((Attribute) iterator.next()).toString() + "\n");
            }
        }
        return str.toString();
    }
}
