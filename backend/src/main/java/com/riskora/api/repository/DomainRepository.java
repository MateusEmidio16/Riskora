package com.riskora.api.repository;

import com.riskora.api.entity.Domain;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DomainRepository extends JpaRepository<Domain, Long> {
    Optional<Domain> findByHostname(String hostname);
    boolean existsByHostname(String hostname);
}
