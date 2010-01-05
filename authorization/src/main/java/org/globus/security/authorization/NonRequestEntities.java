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
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.globus.security.authorization.util.AttributeUtil;

/**
 * Data type returned by collectAttribute method in {@link PIP PIP}
 *
 * @see PIP#collectAttributes(RequestEntities)
 */
public class NonRequestEntities implements Serializable {


    private List subjectAttrCollection;
    private List actionAttrCollection;
    private List resourceAttrCollection;

    public NonRequestEntities() {

        this.subjectAttrCollection = new Vector();
        this.actionAttrCollection = new Vector();
        this.resourceAttrCollection = new Vector();
    }

    /**
     * @param subjectAttrCollection_  Collection of EntityAttributes for subject entities
     * @param actionAttrCollection_   Collection of EntityAttributes for action entities
     * @param resourceAttrCollection_ Collection of EntityAttributes for resource entities
     */
    public NonRequestEntities(List subjectAttrCollection_,
                              List actionAttrCollection_,
                              List resourceAttrCollection_) {

        this.subjectAttrCollection = subjectAttrCollection_;
        this.actionAttrCollection = actionAttrCollection_;
        this.resourceAttrCollection = resourceAttrCollection_;
    }

    public List getSubjectAttrsList() {
        return this.subjectAttrCollection;
    }

    public List getActionAttrsList() {
        return this.actionAttrCollection;
    }

    public List getResourceAttrsList() {
        return this.resourceAttrCollection;
    }

    public void merge(NonRequestEntities reqAttr) {

        if (reqAttr == null) {
            return;
        }

        List subjectAttrs = reqAttr.getSubjectAttrsList();
        mergeSubjectAttributes(subjectAttrs);
        List actionAttrs = reqAttr.getActionAttrsList();
        mergeActionAttributes(actionAttrs);
        List resourceAttrs = reqAttr.getResourceAttrsList();
        mergeResourceAttributes(resourceAttrs);
    }

    public void mergeSubjectAttributes(List subjectAttrs) {

        mergeLists(this.subjectAttrCollection, subjectAttrs);
    }

    public void mergeActionAttributes(List actionAttrs) {

        mergeLists(this.actionAttrCollection, actionAttrs);
    }

    public void mergeResourceAttributes(List resourceAttrs) {

        mergeLists(this.resourceAttrCollection, resourceAttrs);
    }

    protected void mergeLists(List storeList, List mergeList) {

        if (mergeList == null) {
            return;
        }

        Iterator mergeIterator = mergeList.iterator();
        while (mergeIterator.hasNext()) {
            EntityAttributes attr = (EntityAttributes) mergeIterator.next();
            EntityAttributes storeAttr =
                    AttributeUtil.getMatchedEntity(storeList, attr);
            if (storeAttr != null) {
                storeAttr.mergeEntities(attr);
            } else {
                storeList.add(attr);
            }
        }
    }
}
