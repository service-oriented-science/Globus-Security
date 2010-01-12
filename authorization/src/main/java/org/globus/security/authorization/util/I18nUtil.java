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
package org.globus.security.authorization.util;

import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * * Copied as is from CoG JGlobus code
 * <p/>
 * An utility class for internationalized message handling.
 * Example usage::
 * <pre>
 * private static I18n i18n = I18n.getI18n("org.globus.resource");
 * ...
 * public void hello() {
 *    String filename = "file1";
 *    String msg = i18n.getMessage("noFile", new String[]{filename});
 *    ...
 * }
 * </pre>
 */
public class I18nUtil {

    private static Map<String, I18nUtil> mapping = new HashMap<String, I18nUtil>();

    private ResourceBundle messages;

    protected I18nUtil(ResourceBundle messages) {
        this.messages = messages;
    }

    /**
     * Retrieve a I18n instance by resource name.
     *
     * @param resource resource name. See {@link
     *                 ResourceBundle#getBundle(String) ResourceBundle.getBundle()}
     *
     * @return Fill Me
     *
     */
    public static synchronized I18nUtil getI18n(String resource) {
        I18nUtil instance = mapping.get(resource);
        if (instance == null) {
            instance = new I18nUtil(ResourceBundle.getBundle(resource,
                Locale.getDefault(),
                getClassLoader()));
            mapping.put(resource, instance);
        }
        return instance;
    }

    /**
     * Retrieve a I18n instance by resource name
     *
     * @param resource resource name. See {@link
     *                 ResourceBundle#getBundle(String) ResourceBundle.getBundle()}
     * @param loader   the class loader to be used to load
     *                 the resource. This parameter is only used
     *                 initially to load the actual resource. Once the resource
     *                 is loaded, this argument is ignored.
     * @return Fill Me
     */
    public static synchronized I18nUtil getI18n(String resource, ClassLoader loader) {
        I18nUtil instance = mapping.get(resource);
        if (instance == null) {
            //  if (loader == null) {
            //    loader = getClassLoader();
            //}
            instance = new I18nUtil(ResourceBundle.
                getBundle(resource, Locale.getDefault(), loader));
            mapping.put(resource, instance);
        }
        return instance;
    }

    private static ClassLoader getClassLoader() {

        return Thread.currentThread().getContextClassLoader();
    }

    /**
     * Gets a message from resource bundle.
     *
     * @param key Fill Me
     * @return Fill Me
     *
     * @throws MissingResourceException Fill Me
     */
    public String getMessage(String key) throws MissingResourceException {
        return messages.getString(key);
    }

    /**
     * Gets a formatted message from resource bundle
     *
     * @param key Fill Me
     * @param arg Fill Me
     *
     * @return Fill Me
     *
     * @throws MissingResourceException Fill Me
     */
    public String getMessage(String key, Object arg) throws MissingResourceException {
        return getMessage(key, new Object[]{arg});
    }

    /**
     * Gets a formatted message from resource bundle
     *
     * @param key Fill Me
     * @param vars Fill Me
     *
     * @return Fill Me
     *
     * @throws MissingResourceException Fill Me
     */
    public String getMessage(String key, Object[] vars) throws MissingResourceException {
        return MessageFormat.format(messages.getString(key), vars);
    }

}
