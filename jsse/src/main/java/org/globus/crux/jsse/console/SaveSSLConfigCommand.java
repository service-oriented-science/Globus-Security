package org.globus.crux.jsse.console;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.karaf.shell.console.OsgiCommandSupport;
import org.globus.crux.jsse.SSLConfiguratorHolder;
import org.globus.crux.jsse.SecurityStoreManager;

import static org.globus.crux.jsse.console.CreateSSLConfigCommand.*;

@Command(scope = "crux-jsse", name = "saveSSLConfig", description = "Save the SSL Configuration currently being edited")
public class SaveSSLConfigCommand extends OsgiCommandSupport {

	private SecurityStoreManager manager;

	@Override
	protected Object doExecute() throws Exception {
		SSLConfiguratorHolder config = (SSLConfiguratorHolder) session.get(CRUX_SSL_CONFIG_HOLDER);
		if (config == null) {
			System.out.println("There is no configuration currently being edited");
			return null;
		}
		manager.addSSLConfiguration(config);
		session.put(CRUX_SSL_CONFIG_HOLDER, null);
		return null;
	}

	public SecurityStoreManager getManager() {
		return manager;
	}

	public void setManager(SecurityStoreManager manager) {
		this.manager = manager;
	}

}
