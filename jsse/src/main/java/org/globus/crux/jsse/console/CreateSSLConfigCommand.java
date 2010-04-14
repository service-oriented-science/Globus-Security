package org.globus.crux.jsse.console;

import org.apache.felix.gogo.commands.Argument;
import org.apache.felix.gogo.commands.Command;
import org.apache.felix.karaf.shell.console.OsgiCommandSupport;
import org.globus.crux.jsse.SSLConfiguratorHolder;
import org.globus.crux.jsse.SecurityStoreManager;

@Command(scope = "crux-jsse", name = "editSSLConfig", description = "Create or edit an SSL Configuration")
public class CreateSSLConfigCommand extends OsgiCommandSupport {
	public static final String CRUX_SSL_CONFIG_HOLDER = "org.globus.crux.ssl.config.instance";

	@Argument(index = 0, name = "pid", description = "PID of the SSL configuration", required = true, multiValued = false)
	String pid;
	
	@Argument(index = 1, name = "keyStore", description = "Keystore containing the credentials for the SSL configuration", required = true, multiValued = false)
	String keyStoreName;
	
	@Argument(index = 2, name = "trustStore", description = "Store containing the trusted certificates for the SSL configuration", required = true, multiValued = false)
	String trustStoreName;
	
	@Argument(index = 3, name = "crlStore", description = "Store containing the the SSL configuration", required = true, multiValued = false)
	String crlStoreName;
	
	@Argument(index = 4, name = "policyStore", description = "PID of the SSL configuration", required = true, multiValued = false)
	String policyStore;

	private SecurityStoreManager manager;
		
	public SecurityStoreManager getManager() {
		return manager;
	}


	public void setManager(SecurityStoreManager manager) {
		this.manager = manager;
	}


	@Override
	protected Object doExecute() throws Exception {
		if (this.session.get(CRUX_SSL_CONFIG_HOLDER) != null) {
			System.out.println("Another SSL Configuration is currently being edited.");
			return null;
		}
		SSLConfiguratorHolder holder = new SSLConfiguratorHolder();
		holder.setName(pid);
		this.session.put(CRUX_SSL_CONFIG_HOLDER, holder);
		return null;
	}

}
