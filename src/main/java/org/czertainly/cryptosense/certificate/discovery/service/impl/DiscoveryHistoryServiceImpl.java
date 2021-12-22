package org.czertainly.cryptosense.certificate.discovery.service.impl;

import javax.transaction.Transactional;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.discovery.DiscoveryProviderDto;
import com.czertainly.api.model.discovery.DiscoveryStatus;
import org.czertainly.cryptosense.certificate.discovery.repository.DiscoveryHistoryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import org.czertainly.cryptosense.certificate.discovery.dao.DiscoveryHistory;
import org.czertainly.cryptosense.certificate.discovery.service.DiscoveryHistoryService;

import java.util.UUID;

@Service
@Transactional
public class DiscoveryHistoryServiceImpl implements DiscoveryHistoryService {

	private static final Logger logger = LoggerFactory.getLogger(DiscoveryHistoryServiceImpl.class);

	@Autowired
	private DiscoveryHistoryRepository discoveryHistoryRepository;

	@Override
	public DiscoveryHistory addHistory(DiscoveryProviderDto request) {
		logger.debug("Adding a new entry to the database for the discovery with name {}", request.getName());
		DiscoveryHistory modal = new DiscoveryHistory();
		modal.setUuid(UUID.randomUUID().toString());
		modal.setName(request.getName());
		modal.setStatus(DiscoveryStatus.IN_PROGRESS);
		discoveryHistoryRepository.save(modal);
		return modal;
	}

	@Override
	public DiscoveryHistory getHistoryById(Long id) throws NotFoundException {
		logger.info("Finding the Discovery history record for ID {}", id);
		return discoveryHistoryRepository.findById(id).orElseThrow(() -> new NotFoundException(DiscoveryHistoryServiceImpl.class, id));
	}

	@Override
	public DiscoveryHistory getHistoryByUuid(String uuid) throws NotFoundException {
		logger.info("Finding the Discovery history record for uuid {}", uuid);
		return discoveryHistoryRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(DiscoveryHistoryServiceImpl.class, uuid));
	}
	
	public void setHistory(DiscoveryHistory history) {
		discoveryHistoryRepository.save(history);
	}
}
