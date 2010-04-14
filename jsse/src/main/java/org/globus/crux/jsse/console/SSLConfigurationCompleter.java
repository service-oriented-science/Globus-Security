package org.globus.crux.jsse.console;

import java.util.List;

import org.apache.felix.karaf.shell.console.Completer;
import org.apache.felix.karaf.shell.console.completer.ArgumentCompleter;
import org.apache.felix.karaf.shell.console.completer.StringsCompleter;
import org.globus.crux.jsse.SecurityStoreManager;
import org.globus.crux.jsse.SecurityStoreManager.StoreMetadata;

public class SSLConfigurationCompleter implements Completer {

	private SecurityStoreManager manager;
		
	
	public void setManager(SecurityStoreManager configurations) {
		this.manager = configurations;
	}

	@SuppressWarnings("unchecked")
	public int complete(final String buffer, final int cursor, final List candidates) {
		if(manager.getSSLConfiguratorMetadata().size() == 0){
			System.out.println("There are no SSL Configurations currently registered.");
		}
		 StringsCompleter delegate = new StringsCompleter();
		 for(StoreMetadata config: manager.getSSLConfiguratorMetadata()){
			 delegate.getStrings().add(config.getName());
		 }
		return new ArgumentCompleter(delegate).complete(buffer, cursor, candidates);
	}

}
