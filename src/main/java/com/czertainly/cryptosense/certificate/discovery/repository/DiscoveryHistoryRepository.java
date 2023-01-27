package com.czertainly.cryptosense.certificate.discovery.repository;

import com.czertainly.cryptosense.certificate.discovery.dao.DiscoveryHistory;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@Transactional
public interface DiscoveryHistoryRepository extends JpaRepository<DiscoveryHistory, Long>{
	Optional<DiscoveryHistory> findById(Long Id);
	Optional<DiscoveryHistory> findByUuid(String uuid);
}