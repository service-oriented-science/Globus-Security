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
package org.globus.security.authorization.jaas;


import javax.security.auth.Subject;

import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Stack;

/**
 * An implementation of the <code>JaasSubject</code> API to circumvent
 * the JAAS problem of Subject propagation. The implementation uses
 * a stackable version of
 * {@link java.lang.InheritableThreadLocal InheritableThreadLocal}
 * class to associate the Subject object with the current thread.
 * Any new thread started within a thread that has a Subject object
 * associated with it, will inherit the parent's Subject object.
 * Also, nested <code>doAs</code>, <code>runAs</code> calls are supported.
 */
public class GlobusSubject extends JaasSubject {

    private static StackableInheritableThreadLocal<Subject> subjects = new StackableInheritableThreadLocal<Subject>();

    protected GlobusSubject() {
        super();
    }

    public Subject getSubject() {
        return subjects.peek();
    }

    public Object runAs(Subject subject, PrivilegedAction<?> action) {
        subjects.push(subject);
        try {
            return Subject.doAs(subject, action);
        } finally {
            subjects.pop();
        }
    }

    public Object runAs(Subject subject, PrivilegedExceptionAction<?> action)
            throws PrivilegedActionException {
        subjects.push(subject);
        try {
            return Subject.doAs(subject, action);
        } finally {
            subjects.pop();
        }
    }

}

class StackableInheritableThreadLocal<T> extends InheritableThreadLocal<Stack<T>> {

    protected Stack<T> initialValue() {
        return new Stack<T>();
    }

    public StackableInheritableThreadLocal() {
        super();    //To change body of overridden methods use File | Settings | File Templates.
    }

    /**
     * Computes the child's initial value for this inheritable thread-local
     * variable as a function of the parent's value at the time the child
     * thread is created.  This method is called from within the parent
     * thread before the child is started.
     * <p/>
     * This method merely returns its input argument, and should be overridden
     * if a different behavior is desired.
     *
     * @param parentValue the parent thread's value
     * @return the child thread's initial value
     */
    @Override
    protected Stack<T> childValue(Stack<T> parentValue) {
        Stack<T> newList = new Stack<T>();
        if (!parentValue.isEmpty()) {
            newList.push(parentValue.peek());
        }
        return newList;
    }

    public void push(T object) {
        get().push(object);
    }

    public T pop() {
        Stack<T> stack = get();
        return stack.isEmpty() ? null : stack.pop();
    }

    public T peek() {
        Stack<T> stack = get();
        return stack.isEmpty() ? null : stack.peek();
    }

}
