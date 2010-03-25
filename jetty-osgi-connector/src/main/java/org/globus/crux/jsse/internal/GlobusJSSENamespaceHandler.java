package org.globus.crux.jsse.internal;

import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.apache.aries.blueprint.NamespaceHandler;
import org.apache.aries.blueprint.ParserContext;
import org.apache.aries.blueprint.mutable.MutableBeanMetadata;
import org.apache.aries.blueprint.mutable.MutableServiceMetadata;
import org.apache.aries.blueprint.mutable.MutableValueMetadata;
import org.globus.crux.jsse.CRLStoreHolder;
import org.globus.crux.jsse.KeystoreHolder;
import org.globus.crux.jsse.SigningPolicyStoreHolder;
import org.osgi.service.blueprint.container.ComponentDefinitionException;
import org.osgi.service.blueprint.reflect.ComponentMetadata;
import org.osgi.service.blueprint.reflect.Metadata;
import org.osgi.service.blueprint.reflect.ValueMetadata;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class GlobusJSSENamespaceHandler implements NamespaceHandler {

	public ComponentMetadata decorate(Node arg0, ComponentMetadata arg1,
			ParserContext arg2) {
		throw new ComponentDefinitionException(
				"Bad xml syntax: node decoration is not supported");
	}

	@SuppressWarnings("unchecked")
	public Set<Class> getManagedClasses() {
		return new HashSet<Class>(Arrays.asList(CruxKeystore.class,
				FileBasedCertStore.class, CruxSigningPolicyStore.class));
	}

	public URL getSchemaLocation(String arg0) {
		return getClass().getResource(
				"/org/globus/crux/jsse/config/crux-jsse.xsd");
	}

	public Metadata parse(Element element, ParserContext context) {
		String name = element.getLocalName() != null ? element.getLocalName()
				: element.getNodeName();
		if ("pemKeystore".equals(name)) {
			return parseKeystore(element, context);
		} else if ("pemTruststore".equals(name)) {
			return parseTruststore(element, context);
		} else if ("signingPolicyStore".equals(name)) {
			return parseSigningPolicyStore(element, context);
		} else if ("pemCRLstore".equals(name)) {
			return parseCRLstore(element, context);
		}
		throw new ComponentDefinitionException(
				"Bad xml syntax: unknown element '" + name + "'");
	}

	private Metadata parseKeystore(Element element, ParserContext context) {
		MutableBeanMetadata bean = context
				.createMetadata(MutableBeanMetadata.class);
		bean.setRuntimeClass(CruxKeystore.class);
		String name = element.getAttribute("name");
		bean.addProperty("name", createValue(context, name));
		String description = element.getAttribute("description");
		if (description != null) {
			bean.addProperty("description", createValue(context, description));
		}
		String proxyCredentialPath = element
				.getAttribute("proxyCredentialPath");
		if (proxyCredentialPath != null && !proxyCredentialPath.isEmpty()) {
			bean.addProperty("proxyCredentialPath", createValue(context,
					proxyCredentialPath));
		} else {
			String keyPath = element.getAttribute("keyLocation");
			bean.addProperty("keyLocation", createValue(context, keyPath));
			String certPath = element.getAttribute("certLocation");
			bean.addProperty("certificateLocation", createValue(context,
					certPath));
		}
		MutableServiceMetadata service = context
				.createMetadata(MutableServiceMetadata.class);
		service.setId(name);
		service.setServiceComponent(bean);
		service.addInterface(KeystoreHolder.class.getName());
		return service;

	}

	private Metadata parseTruststore(Element element, ParserContext context) {
		MutableBeanMetadata bean = context
				.createMetadata(MutableBeanMetadata.class);
		// bean.setRuntimeClass(FileBasedKeyStore.class);
		// String defaultCertificateDir =
		// element.getAttribute("defaultTrustDirectory");
		// bean.addProperty("defaultTrustDirectory", createValue(context,
		// defaultCertificateDir));
		// String trustDirectories =
		// element.getAttribute("trustedCertLocations");
		// bean.addProperty("trustedCertLocations", createValue(context,
		// trustDirectories));
		// String name = element.getAttribute("name");
		MutableServiceMetadata service = context
				.createMetadata(MutableServiceMetadata.class);
		service.setId("name");
		service.setServiceComponent(bean);
		service.addInterface(KeystoreHolder.class.getName());
		return service;
	}

	private Metadata parseSigningPolicyStore(Element element,
			ParserContext context) {
		MutableBeanMetadata bean = context
				.createMetadata(MutableBeanMetadata.class);
		bean.setRuntimeClass(CruxSigningPolicyStore.class);
		String signingPolicyLocations = element
				.getAttribute("signingPolicyLocations");
		bean.addProperty("signingPolicyLocations", createValue(context,
				signingPolicyLocations));
		String name = element.getAttribute("name");
		MutableServiceMetadata service = context
				.createMetadata(MutableServiceMetadata.class);
		service.setId(name);
		service.setServiceComponent(bean);
		service.addInterface(SigningPolicyStoreHolder.class.getName());
		return service;
	}

	private Metadata parseCRLstore(Element element, ParserContext context) {
		MutableBeanMetadata bean = context
				.createMetadata(MutableBeanMetadata.class);
		bean.setRuntimeClass(FileBasedCertStore.class);
		String crlStoreLocations = element.getAttribute("crlLocations");
		bean.addProperty("crlLocations",
				createValue(context, crlStoreLocations));
		MutableServiceMetadata service = context
				.createMetadata(MutableServiceMetadata.class);
		String name = element.getAttribute("name");
		service.setId(name);
		service.setServiceComponent(bean);
		service.addInterface(CRLStoreHolder.class.getName());
		return service;
	}

	private ValueMetadata createValue(ParserContext context, String value) {
		MutableValueMetadata v = context
				.createMetadata(MutableValueMetadata.class);
		v.setStringValue(value);
		return v;
	}

}
