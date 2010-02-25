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
package org.globus.security.authorization.providers;

import java.util.Iterator;
import java.util.Stack;
import java.util.Vector;

import org.globus.security.authorization.EntityAttributes;

/**
 * Datatype used to store context information while constructing decision chain.
 * Used by PermitOverideAlg.
 */
public class DecisionChainContext {

	private Stack<EntityAttributes> chain;
	private Vector<EntityAttributes> deniedList;
	private EntityAttributes[] authorities;
	private Vector<Throwable> deniedExceptions;

	public DecisionChainContext() {
		this(1);
	}

	public DecisionChainContext(int i) {
		chain = new Stack<EntityAttributes>();
		deniedList = new Vector<EntityAttributes>();
		authorities = new EntityAttributes[i];
	}

	/**
	 * Tests if the specified authority is in the decision chain.
	 * 
	 * @param authority
	 *            Fill Me
	 * @return true if the specified authority is in the decision chain.
	 */
	public boolean isInChain(EntityAttributes authority) {
		return chain.contains(authority);
	}

	/**
	 * Appends the specified authority to the decision chain.
	 * 
	 * @param authority
	 *            Fill Me
	 */
	public void appendToChain(EntityAttributes authority) {
		chain.push(authority);
	}

	/**
	 * Removes the last authority from the decision chain.
	 */
	public void removeFromChain() {
		chain.pop();
	}

	/**
	 * Returns the iterator for the decision chain.
	 * 
	 * @return the iterator for the decision chain.
	 */
	public Iterator<EntityAttributes> getChainAsIterator() {
		return chain.iterator();
	}

	/**
	 * Tests if the specified authority is in the denied list.
	 * 
	 * @param authority
	 *            Fill Me
	 * @return true if the specified authority is in the denied list.
	 */
	public boolean isDenied(EntityAttributes authority) {
		return deniedList.contains(authority);
	}

	public void addToDeniedList(EntityAttributes authority) {
		deniedList.add(authority);
	}

	public EntityAttributes getAuthorityAt(int i) {
		return authorities[i];
	}

	public void setAuthorityAt(int i, EntityAttributes authority) {
		authorities[i] = authority;
	}

	public void addDeniedException(Throwable exception) {

		if (this.deniedExceptions == null) {
			this.deniedExceptions = new Vector<Throwable>();
		}
		if (exception != null) {
			this.deniedExceptions.add(exception);
		}
	}

	public Vector<Throwable> getDeniedExceptions() {
		return this.deniedExceptions;
	}
}
