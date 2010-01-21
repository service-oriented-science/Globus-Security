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
package org.globus.security.util;

import java.lang.reflect.Array;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public final class ArraysUtil {

    private ArraysUtil() {
        //This should not be initialized.
    }

    /**
     * Fill me
     *
     * @param clazz
     * @param array
     * @param length
     * @param <T>
     * @return
     */
    @SuppressWarnings("unchecked")
    public static <T> T[] copyArray(Class<T> clazz, T[] array, int length) {
        Object[] copy = (Object[]) Array.newInstance(clazz, length);
        System.arraycopy(array, 0, copy, 0, length);
        return (T[]) copy;
    }

}
