package org.icatproject.authn_shib2local;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.Id;

@SuppressWarnings("serial")
@Entity
public class FedIdMap implements Serializable {

	@Id
	private String shibId;

	private String localUid;

	// Needed by JPA
	public FedIdMap() {
	}

	public String getLocalUid() {
		return localUid;
	}
}
