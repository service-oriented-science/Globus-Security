package org.globus.crux.jsse;

import java.util.List;

public interface SecurityStoreManager {
	public KeystoreHolder getKeyStore(String name);

	public List<StoreMetadata> getSSLConfiguratorMetadata();

	public SSLConfiguratorHolder getSSLConfiguration(String pid);

	public void addSSLConfiguration(SSLConfiguratorHolder config);

	public List<StoreMetadata> getKeyStoreMetadata();

	public void registerKeyStore(KeystoreHolder store);

	public KeystoreHolder getTrustStore(String name);

	public void registerTrustStore(KeystoreHolder store);

	public CRLStoreHolder getCRLStore(String name);

	public void registerCRLStore(CRLStoreHolder store);

	public SigningPolicyStoreHolder getSigningPolicyStore(String name);

	public void registerPolicyStore(SigningPolicyStoreHolder store);

	public class StoreMetadata {
		private String name;
		private String description;

		public StoreMetadata(String name, String description) {
			super();
			this.name = name;
			this.description = description;
		}

		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}

		public String getDescription() {
			return description;
		}

		public void setDescription(String description) {
			this.description = description;
		}

	}
}
