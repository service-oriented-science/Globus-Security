package org.globus.security.spring;

import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.testng.annotations.Test;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Oct 21, 2009
 * Time: 3:04:17 PM
 * To change this template use File | Settings | File Templates.
 */
public class SpringTest {

    @Test
    public void test() throws Exception {
        ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext("/securityconfig.xml");
        context.getBean("myKeyStore");
    }
}
