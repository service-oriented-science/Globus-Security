package org.globus.crux.main;

import java.security.KeyStore;
import java.security.Security;
import java.security.KeyStore.LoadStoreParameter;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.globus.security.filestore.KeyStoreParametersFactory;
import org.globus.security.jetty.GlobusSslSocketConnector;
import org.globus.security.provider.GlobusProvider;
import org.globus.security.stores.ResourceSigningPolicyStore;
import org.globus.security.stores.ResourceSigningPolicyStoreParameters;
import org.globus.security.util.SSLConfigurator;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.NamespaceHandlerSupport;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class JettyNamespaceHandler extends NamespaceHandlerSupport {

	static {
		Security.addProvider(new GlobusProvider());
	}

	Pattern variablePattern = Pattern.compile("(.*?)\\$\\{([a-zA-Z0-9.]+)\\}");

	public void init() {
		this.registerBeanDefinitionParser("server", new JettyBeanParser());
		this.registerBeanDefinitionParser("gsi", new GSITrustManagerParser());
		this.registerBeanDefinitionParser("sslConnector",
				new SSLConnectorParser());
	}

	private String substituteString(String line) {
		line = line.trim();
		Matcher substitutionMatcher = variablePattern.matcher(line);
		if (substitutionMatcher.find()) {
			StringBuffer buffer = new StringBuffer();
			int lastLocation = 0;
			do {
				String prefix = substitutionMatcher.group(1);
				buffer.append(prefix);
				String key = substitutionMatcher.group(2);
				String value = getValue(key);
				buffer.append(value);
				lastLocation = substitutionMatcher.end();
			} while (substitutionMatcher.find(lastLocation));
			buffer.append(line.substring(lastLocation));
			return buffer.toString();
		} else {
			return line;
		}
	}

	private String getValue(String key) {
		String val = System.getProperty(key);
		if (val == null || val.isEmpty()) {
			val = System.getenv(key);
		}
		if (val != null) {
			return val;
		}
		return "${" + key + "}";

	}

	class SSLConnectorParser extends AbstractSingleBeanDefinitionParser {

		@Override
		protected void doParse(Element element, ParserContext parserContext,
				BeanDefinitionBuilder builder) {
			NodeList children = element.getChildNodes();
			for (int i = 0; i < children.getLength(); i++) {
				if (children.item(i).getNodeType() == Node.ELEMENT_NODE) {
					Element child = (Element) children.item(i);
					if (child.getLocalName().equals("trustManager")) {
						NodeList trustManagers = child.getChildNodes();
						for (int j = 0; j < trustManagers.getLength(); j++) {
							if (trustManagers.item(j).getNodeType() == Node.ELEMENT_NODE) {
								Object trustManager = parserContext
										.getDelegate()
										.parseCustomElement(
												(Element) trustManagers.item(j),
												builder.getBeanDefinition());
								builder.addConstructorArgValue(trustManager);
							}
						}

					}

				}
			}
			String portStr = element.getAttribute("port");
			if (portStr != null && !portStr.isEmpty()) {
				builder.addPropertyValue("port", Integer.valueOf(portStr));
			}
			String clientAuthStr = element.getAttribute("requireClientAuthn");
			if (clientAuthStr != null && !clientAuthStr.isEmpty()) {
				builder.addPropertyValue("needClientAuth", Boolean
						.valueOf(clientAuthStr));
			}
		}

		@Override
		protected Class<?> getBeanClass(Element element) {
			return GlobusSslSocketConnector.class;
		}

	}

	class GSITrustManagerParser extends AbstractSingleBeanDefinitionParser {

		@Override
		protected void doParse(Element element, ParserContext parserContext,
				BeanDefinitionBuilder bean) {
			bean.addPropertyValue("credentialStoreType",
					GlobusProvider.KEYSTORE_TYPE);
			NodeList children = element.getChildNodes();
			try {
				for (int i = 0; i < children.getLength(); i++) {
					Node n = children.item(i);
					if (n.getNodeType() == Node.ELEMENT_NODE) {
						String name = n.getLocalName();
						Element child = (Element) n;
						if (name.equals("credential")) {
							bean.addPropertyValue("credentialStore",
									createCredentialStore(n));
						} else if (name.equals("trustedCertLocations")) {
							bean.addPropertyValue("trustAnchorStore",
									createTrustStore(child));
						} else if (name.equals("crlLocations")) {
							bean.addPropertyValue("crlStoreType",
									GlobusProvider.CERTSTORE_TYPE);
							bean.addPropertyValue("crlLocationPattern",
									substituteString(child.getTextContent()));
						} else if (name.equals("signingPolicyLocations")) {
							ResourceSigningPolicyStoreParameters params = new ResourceSigningPolicyStoreParameters(
									substituteString(substituteString(child
											.getTextContent())));
							bean.addPropertyValue("policyStore",
									new ResourceSigningPolicyStore(params));
						}
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
				// TODO: handle exception
			}
		}

		private KeyStore createTrustStore(Element element) throws Exception {
			KeyStore trustStore = KeyStore
					.getInstance(GlobusProvider.KEYSTORE_TYPE);
			trustStore.load(KeyStoreParametersFactory
					.createTrustStoreParameters(substituteString(element
							.getTextContent())));
			return trustStore;
		}

		private KeyStore createCredentialStore(Node n) throws Exception {
			NodeList children = n.getChildNodes();
			String proxyCredentialLocation = null;
			String keyLocation = null;
			String certificateLocation = null;
			for (int i = 0; i < children.getLength(); i++) {
				Node child = children.item(i);
				if (child.getNodeType() != Node.ELEMENT_NODE) {
					continue;
				}
				if (n.getLocalName().equals("proxyCredentialLocation")) {
					proxyCredentialLocation = substituteString(child
							.getFirstChild().getTextContent());

				} else if (child.getLocalName().equals("keyLocation")) {
					keyLocation = substituteString(child.getFirstChild()
							.getTextContent());
				} else if (child.getLocalName().equals("certificateLocation")) {
					certificateLocation = substituteString(child
							.getFirstChild().getTextContent());
				}
			}
			LoadStoreParameter params = null;
			if (proxyCredentialLocation != null
					&& !proxyCredentialLocation.isEmpty()) {
				params = KeyStoreParametersFactory
						.createProxyCertParameters(proxyCredentialLocation);
			} else {
				params = KeyStoreParametersFactory.createCertKeyParameters(
						certificateLocation, keyLocation);
			}
			KeyStore keyStore = KeyStore
					.getInstance(GlobusProvider.KEYSTORE_TYPE);
			keyStore.load(params);
			return keyStore;
		}

		@Override
		protected Class<?> getBeanClass(Element element) {
			return SSLConfigurator.class;
		}

	}

	class JettyBeanParser extends AbstractSingleBeanDefinitionParser {

		@Override
		protected Class<?> getBeanClass(Element element) {
			return JettyLauncher.class;
		}

		@Override
		protected void doParse(Element element, ParserContext parserContext,
				BeanDefinitionBuilder bean) {
			NodeList children = element.getElementsByTagName("connectors");
			for (int i = 0; i < children.getLength(); i++) {
				Node n = children.item(i);
				if (n.getNodeType() == Node.ELEMENT_NODE) {
					List<?> connectors = parserContext.getDelegate()
							.parseListElement((Element) n,
									bean.getBeanDefinition());
					bean.addPropertyValue("connectors", connectors);
				}
			}
		}
	}
}
