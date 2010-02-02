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

import org.globus.security.authorization.xml.AuthZChain;
import org.globus.security.authorization.xml.SecurityDescriptor;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 26, 2010
 * Time: 3:35:39 PM
 * To change this template use File | Settings | File Templates.
 */
@Test
public class TestLoadSpringConfig {

    public void test1() throws Exception {
        ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext("/sampleBeanContext.xml");
        SecurityDescriptor descriptor = context.getBean(SecurityDescriptor.class);
        AuthZChain chain = descriptor.getAuthzChain();
        assertEquals(chain.getPdps().size(), 3);


    }
}
