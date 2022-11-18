package com.czertainly.cryptosense.certificate.discovery.dao;

import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "cryptosense_discovery_history")
public class DiscoveryHistory extends Audited implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 571684590427678474L;

	@Id
	@Column(name = "id")
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "cryptosense_discovery_seq")
	@SequenceGenerator(name = "cryptosense_discovery_seq", sequenceName = "cryptosense_discovery_id_seq", allocationSize = 1)
	private Long id;

	@Column(name="uuid")
	private String uuid;

	@Column(name = "name")
	private String name;

	@Column(name = "status")
	@Enumerated(EnumType.STRING)
	private DiscoveryStatus status;
	
	@Column(name = "meta")
	private String meta;

	@Override
	public String toString() {
		return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE).append("id", id).append("name", name)
				.append("status", status).toString();
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public DiscoveryStatus getStatus() {
		return status;
	}

	public void setStatus(DiscoveryStatus status) {
		this.status = status;
	}

	public String getMeta() {
		return meta;
	}

	public void setMeta(String meta) {
		this.meta = meta;
	}

}
