package org.czertainly.cryptosense.certificate.discovery.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.discovery.DiscoveryProviderDto;
import org.czertainly.cryptosense.certificate.discovery.dao.DiscoveryHistory;

public interface DiscoveryHistoryService {
	public DiscoveryHistory addHistory(DiscoveryProviderDto request);
	public DiscoveryHistory getHistoryById(Long id) throws NotFoundException;
	public void setHistory(DiscoveryHistory history);
}
