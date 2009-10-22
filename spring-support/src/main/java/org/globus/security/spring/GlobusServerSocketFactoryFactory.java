package org.globus.security.spring;

import org.globus.security.util.SSLConfigurator;
import org.springframework.beans.factory.FactoryBean;

import javax.net.ssl.SSLServerSocketFactory;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Oct 21, 2009
 * Time: 2:36:23 PM
 * To change this template use File | Settings | File Templates.
 */
public class GlobusServerSocketFactoryFactory extends SSLConfigurator
        implements FactoryBean<SSLServerSocketFactory> {

    public SSLServerSocketFactory getObject() throws Exception {
        return super.createServerFactory();
    }

    public Class<? extends SSLServerSocketFactory> getObjectType() {
        return SSLServerSocketFactory.class;
    }

    public boolean isSingleton() {
        return true;
    }
}
