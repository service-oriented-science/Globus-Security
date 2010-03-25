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
package org.globus.security.jaas;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.security.auth.Subject;

import org.globus.security.JAASTest;
import org.globus.security.SecurityTest;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category( { SecurityTest.class, JAASTest.class })
public class GlobusSubjectTest {

	private static final String CRED = "testCred1";
	private static final String CRED2 = "testCred2";

	@Test
	public void testSubject() throws Exception {

		Subject subject = new Subject();
		subject.getPublicCredentials().add(CRED);

		TestAction action = new TestAction();
		JaasSubject.doAs(subject, action);

		assertThat(subject, is(action.subject1));
		assertThat(subject, is(action.innerSubject));
		assertThat(subject, is(action.subject2));
	}

	class TestAction implements PrivilegedAction<Object> {

		Subject subject1, innerSubject, subject2;

		public Object run() {
			this.subject1 = JaasSubject.getCurrentSubject();
			this.innerSubject = (Subject) AccessController.doPrivileged(new PrivilegedAction<Object>() {
				public Object run() {
					return JaasSubject.getCurrentSubject();
				}
			});
			this.subject2 = JaasSubject.getCurrentSubject();
			return null;
		}
	}

	public void testNestedSubject() throws Exception {

		Subject subject = new Subject();
		subject.getPublicCredentials().add(CRED);

		Subject anotherSubject = new Subject();
		anotherSubject.getPublicCredentials().add(CRED2);

		NestedTestAction action = new NestedTestAction(anotherSubject);
		JaasSubject.doAs(subject, action);

		assertEquals(subject, action.subject1);
		assertEquals(subject, action.subject2);

		assertEquals(anotherSubject, action.innerSubject1);
		assertEquals(anotherSubject, action.innerSubject2);
		assertEquals(anotherSubject, action.innerInnerSubject);
	}

	class NestedTestAction implements PrivilegedAction {

		Subject subject1, subject2;
		Subject innerSubject1, innerSubject2, innerInnerSubject;

		Subject anotherSubject;

		public NestedTestAction(Subject anotherSubject) {
			this.anotherSubject = anotherSubject;
		}

		public Object run() {
			this.subject1 = JaasSubject.getCurrentSubject();

			TestAction action = new TestAction();
			JaasSubject.doAs(anotherSubject, action);

			this.innerSubject1 = action.subject1;
			this.innerSubject2 = action.subject2;
			this.innerInnerSubject = action.innerSubject;

			this.subject2 = JaasSubject.getCurrentSubject();
			return null;
		}
	}

	public void testGetSubjectSameThread() throws Exception {

		Subject subject = new Subject();
		subject.getPublicCredentials().add(CRED);

		SimpleTestAction action = new SimpleTestAction();
		Subject returnedSubject = (Subject) JaasSubject.doAs(subject, action);

		assertEquals(subject, returnedSubject);
	}

	class SimpleTestAction implements PrivilegedAction {
		public Object run() {
			return JaasSubject.getCurrentSubject();
		}
	}

	public void testGetSubjectInheritThread() throws Exception {

		Subject subject = new Subject();
		subject.getPublicCredentials().add(CRED);

		ThreadTestAction action = new ThreadTestAction();
		Subject returnedSubject = (Subject) JaasSubject.doAs(subject, action);

		assertEquals(subject, returnedSubject);
	}

	class ThreadTestAction implements PrivilegedAction {
		public Object run() {
			TestThread t = new TestThread();
			t.start();
			try {
				t.join();
			} catch (Exception e) {
			}
			return t.subject;
		}
	}

	class TestThread extends Thread {
		Subject subject;

		public void run() {
			this.subject = JaasSubject.getCurrentSubject();
		}
	}

}
