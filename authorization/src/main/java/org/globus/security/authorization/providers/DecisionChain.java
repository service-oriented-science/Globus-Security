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
package org.globus.security.authorization.providers;

import org.globus.security.authorization.Decision;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;

/**
 * Data type used to store decision chain (as it is being
 * constructed). Used by PermitOverideAlg
 */
public class DecisionChain {

    /**
     * a Vector that represents the authorization decision chain
     */
    private List<Decision> chain = new Vector<Decision>();

    /**
     * Adds the decision to the chain.
     *
     * @param decision
     */
    public void add(Decision decision) {
        chain.add(decision);
    }

    /**
     * Removes the decision from the chain.
     * This method removes the first occurrence of the decision specified
     * by the argument from the chain.
     *
     * @param decision a decision to remove.
     * @return true if it successfully remove the decision.
     */
    public boolean remove(Decision decision) {
        return chain.remove(decision);
    }

    /**
     * Returns the iterator for the chain.
     *
     * @return the iterator for the chain.
     */
    public Iterator<Decision> iterator() {
        return chain.iterator();
    }

    /**
     * @param decision
     * @return if the specified decision is in the chain.
     */
    public boolean contains(Decision decision) {
        return chain.contains(decision);
    }

    /**
     * @param index
     * @return the Decision at given index.
     */
    public Decision elementAt(int index) {
        return chain.get(index);
    }

    /**
     * @return true if the decision chain is empty.
     */
    public boolean isEmpty() {
        return chain.size() == 0;
    }

    /**
     * @return the size of the decision chain.
     */
    public int size() {
        return chain.size();
    }

    /**
     * @return the array representation of the decision chain.
     */
    public Decision[] toArray() {
        if (chain == null) {
            return null;
        }
        int count = chain.size();
        Decision[] decisions = new Decision[count];
        chain.toArray(decisions);
        return decisions;
    }
}
