package org.czertainly.cryptosense.certificate.discovery.service;

import java.io.IOException;


import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.discovery.DiscoveryProviderDto;

import org.czertainly.cryptosense.certificate.discovery.dao.DiscoveryHistory;

public interface DiscoveryService {
	public void discoverCertificate(DiscoveryProviderDto request, DiscoveryHistory history) throws IOException, NotFoundException;

	public DiscoveryProviderDto getProviderDtoData(DiscoveryProviderDto request, DiscoveryHistory history);
}
