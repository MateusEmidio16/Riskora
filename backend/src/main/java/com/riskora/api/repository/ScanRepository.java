package com.riskora.api.repository;

import com.riskora.api.entity.Scan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanRepository extends JpaRepository<Scan, Long> {
    List<Scan> findByDomainIdOrderByCreatedAtDesc(Long domainId);
}
