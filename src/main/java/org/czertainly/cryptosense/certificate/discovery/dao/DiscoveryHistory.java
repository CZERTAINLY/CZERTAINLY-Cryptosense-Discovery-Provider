package org.czertainly.cryptosense.certificate.discovery.dao;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;

import com.czertainly.api.model.discovery.DiscoveryStatus;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

@Entity
@Table(name = "cryptosense_discovery_history")
public class DiscoveryHistory extends Audited implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 571684590427678474L;

	@Id
	@Column(name = "id")
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "ip_discovery_seq")
	@SequenceGenerator(name = "ip_discovery_seq", sequenceName = "ip_discovery_id_seq", allocationSize = 1)
	private Long id;

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
