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
package org.globus.security.authorization;

import org.globus.security.authorization.util.AttributeUtil;

import java.io.Serializable;
import java.util.List;
import java.util.Vector;

/**
 * Data type returned by collectAttribute method in {@link PIP PIP}
 *
 * @see PIP#collectAttributes(RequestEntities)
 */
public class NonRequestEntities implements Serializable {

    private static final long serialVersionUID = 7191178873283695083L;

    private List<EntityAttributes> subjectAttrCollection;
    private List<EntityAttributes> actionAttrCollection;
    private List<EntityAttributes> resourceAttrCollection;

    public NonRequestEntities() {

        this.subjectAttrCollection = new Vector<EntityAttributes>();
        this.actionAttrCollection = new Vector<EntityAttributes>();
        this.resourceAttrCollection = new Vector<EntityAttributes>();
    }

    /**
     * @param initSubjectAttrCollection  Collection of EntityAttributes for subject entities
     * @param initActionAttrCollection   Collection of EntityAttributes for action entities
     * @param initResourceAttrCollection Collection of EntityAttributes for resource entities
     */
    public NonRequestEntities(List<EntityAttributes> initSubjectAttrCollection, List<EntityAttributes> initActionAttrCollection,
                              List<EntityAttributes> initResourceAttrCollection) {

        this.subjectAttrCollection = initSubjectAttrCollection;
        this.actionAttrCollection = initActionAttrCollection;
        this.resourceAttrCollection = initResourceAttrCollection;
    }

    public List<EntityAttributes> getSubjectAttrsList() {
        return this.subjectAttrCollection;
    }

    public List<EntityAttributes> getActionAttrsList() {
        return this.actionAttrCollection;
    }

    public List<EntityAttributes> getResourceAttrsList() {
        return this.resourceAttrCollection;
    }

    public void merge(NonRequestEntities reqAttr) {

        if (reqAttr == null) {
            return;
        }

        List<EntityAttributes> subjectAttrs = reqAttr.getSubjectAttrsList();
        mergeSubjectAttributes(subjectAttrs);
        List<EntityAttributes> actionAttrs = reqAttr.getActionAttrsList();
        mergeActionAttributes(actionAttrs);
        List<EntityAttributes> resourceAttrs = reqAttr.getResourceAttrsList();
        mergeResourceAttributes(resourceAttrs);
    }

    public void mergeSubjectAttributes(List<EntityAttributes> subjectAttrs) {

        mergeLists(this.subjectAttrCollection, subjectAttrs);
    }

    public void mergeActionAttributes(List<EntityAttributes> actionAttrs) {

        mergeLists(this.actionAttrCollection, actionAttrs);
    }

    public void mergeResourceAttributes(List<EntityAttributes> resourceAttrs) {

        mergeLists(this.resourceAttrCollection, resourceAttrs);
    }

    protected void mergeLists(List<EntityAttributes> storeList, List<EntityAttributes> mergeList) {

        if (mergeList == null) {
            return;
        }

        for (Object aMergeList : mergeList) {
            EntityAttributes attr = (EntityAttributes) aMergeList;
            EntityAttributes storeAttr = AttributeUtil.getMatchedEntity(storeList, attr);
            if (storeAttr != null) {
                storeAttr.mergeEntities(attr);
            } else {
                storeList.add(attr);
            }
        }
    }
}
