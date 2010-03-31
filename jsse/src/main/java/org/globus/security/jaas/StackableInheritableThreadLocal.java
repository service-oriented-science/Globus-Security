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

package org.globus.security.jaas;

import java.util.Stack;

/**
 *
 * @param <T> Type of object in the stack
 *
 * @since 1.0
 * @version 1.0
 */
public class StackableInheritableThreadLocal<T> extends InheritableThreadLocal<Stack<T>> {

    protected Stack<T> initialValue() {
        return new Stack<T>();
    }

    protected Stack<T> childValue(Stack<T> parentValue) {
        Stack<T> newList = new Stack<T>();
        if (parentValue.size() > 0) {
            newList.add(parentValue.peek());
        }
        return newList;
    }

    public void push(T object) {
        get().push(object);
    }

    public T pop() {
        return (get().size() == 0) ? null : get().pop();
    }

    public Object peek() {
        return (get().size() == 0) ? null : get().peek();
    }

}
