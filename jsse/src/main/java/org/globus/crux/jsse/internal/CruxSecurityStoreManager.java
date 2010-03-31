package org.globus.crux.jsse.internal;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.globus.crux.jsse.CRLStoreHolder;
import org.globus.crux.jsse.KeystoreHolder;
import org.globus.crux.jsse.SSLConfiguratorHolder;
import org.globus.crux.jsse.SecurityStoreManager;
import org.globus.crux.jsse.SigningPolicyStoreHolder;

public class CruxSecurityStoreManager implements SecurityStoreManager {
	private List<KeystoreHolder> keyStoreList;
	private Map<String, KeystoreHolder> localKeyStores = new HashMap<String, KeystoreHolder>();
	private Map<String, SSLConfiguratorHolder> configurations = new HashMap<String, SSLConfiguratorHolder>();
	private List<KeystoreHolder> trustStoreList;
	private Map<String, KeystoreHolder> localTrustStores = new HashMap<String, KeystoreHolder>();
	private List<CRLStoreHolder> crlStoreList;
	private Map<String, CRLStoreHolder> localCrlStores = new HashMap<String, CRLStoreHolder>();
	private List<SigningPolicyStoreHolder> policyStoreList;
	private Map<String, SigningPolicyStoreHolder> localPolicyStores = new HashMap<String, SigningPolicyStoreHolder>();

	public CruxSecurityStoreManager() throws Exception {
		KeyStore keystore = KeyStore.getInstance("PEMFilebasedKeyStore");
	}

	public SSLConfiguratorHolder getSSLConfiguration(String pid) {
		return configurations.get(pid);
	}

	public void addSSLConfiguration(SSLConfiguratorHolder config) {
		configurations.put(config.getName(), config);
	}

	public List<StoreMetadata> getSSLConfiguratorMetadata() {
		List<StoreMetadata> configs = new ArrayList<StoreMetadata>();
		for (SSLConfiguratorHolder config : configurations.values()) {
			configs.add(new StoreMetadata(config.getName(), config
					.getDescription()));
		}
		return configs;
	}

	public CRLStoreHolder getCRLStore(String name) {
		CRLStoreHolder result = localCrlStores.get(name);
		if (result == null) {
			for (CRLStoreHolder crlStore : crlStoreList) {
				if (crlStore.getName().equals(name)) {
					result = crlStore;
				}
			}
		}
		return result;
	}

	public KeystoreHolder getKeyStore(String name) {
		KeystoreHolder result = localKeyStores.get(name);
		if (result == null) {
			for (KeystoreHolder store : keyStoreList) {
				if (store.getName().equals(name)) {
					result = store;
				}
			}
		}
		return result;
	}

	public SigningPolicyStoreHolder getSigningPolicyStore(String name) {
		SigningPolicyStoreHolder result = localPolicyStores.get(name);
		if (result == null) {
			for (SigningPolicyStoreHolder store : policyStoreList) {
				if (store.getName().equals(name)) {
					result = store;
				}
			}
		}
		return result;
	}

	public KeystoreHolder getTrustStore(String name) {
		KeystoreHolder result = localTrustStores.get(name);
		for (KeystoreHolder store : trustStoreList) {
			if (store.getName().equals(name)) {
				result = store;
			}
		}
		return result;
	}

	public void registerCRLStore(CRLStoreHolder store) {
		localCrlStores.put(store.getName(), store);
	}

	public void registerKeyStore(KeystoreHolder store) {
		localKeyStores.put(store.getName(), store);
	}

	public void registerPolicyStore(SigningPolicyStoreHolder store) {
		localPolicyStores.put(store.getName(), store);
	}

	public void registerTrustStore(KeystoreHolder store) {
		localTrustStores.put(store.getName(), store);
	}

	public void setKeyStoreList(List<KeystoreHolder> keyStoreList) {
		this.keyStoreList = keyStoreList;
	}

	public void setTrustStoreList(List<KeystoreHolder> trustStoreList) {
		this.trustStoreList = trustStoreList;
	}

	public void setCrlStoreList(List<CRLStoreHolder> crlStoreList) {
		this.crlStoreList = crlStoreList;
	}

	public void setPolicyStoreList(
			List<SigningPolicyStoreHolder> policyStoreList) {
		this.policyStoreList = policyStoreList;
	}

	public List<StoreMetadata> getKeyStoreMetadata() {
		List<StoreMetadata> result = new ArrayList<StoreMetadata>();
		for (KeystoreHolder store : localKeyStores.values()) {
			result.add(new StoreMetadata(store.getName(), store
					.getDescription()));
		}
		for (KeystoreHolder store : keyStoreList) {
			result.add(new StoreMetadata(store.getName(), store
					.getDescription()));
		}
		return Collections.unmodifiableList(result);
	}

}
