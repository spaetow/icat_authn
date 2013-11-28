package org.icatproject.authn_shib2local;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.Id;

@SuppressWarnings("serial")
@Entity
public class AccountIdMap implements Serializable {

	@Id
	private String external_Id;

	private String local_Uid;

	// Needed by JPA
	public AccountIdMap() {
	}

	public String getLocalUid() {
		return local_Uid;
	}
}
