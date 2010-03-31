package org.globus.crux.jsse.console;

import java.util.List;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.karaf.shell.console.OsgiCommandSupport;
import org.globus.crux.jsse.SecurityStoreManager;
import org.globus.crux.jsse.SecurityStoreManager.StoreMetadata;

@Command(scope = "crux-jsse", name = "listKeystores", description = "List the KeyStores currently registered with this container")
public class KeystoreCommand extends OsgiCommandSupport {
	private SecurityStoreManager stores;

	//	private Logger logger = LoggerFactory.getLogger(getClass());

	@Override
	protected Object doExecute() throws Exception {
		List<StoreMetadata> keystores = stores.getKeyStoreMetadata();

		System.out.println((keystores == null || keystores.size() == 0) ? "No registered KeyStores"
				: getKeyStoreInfo(keystores));
		return null;
	}

	private String getKeyStoreInfo(List<StoreMetadata> keystores) {
		StringBuilder builder = new StringBuilder();
		int lineno = 1;
		for (StoreMetadata keystore : keystores) {
			builder.append(String.format("[%4d]  ", lineno++) + keystore.getName() + " : " + keystore.getDescription());
		}
		return builder.toString();
	}

	public SecurityStoreManager getStores() {
		return stores;
	}

	public void setStores(SecurityStoreManager stores) {
		this.stores = stores;
	}

}
