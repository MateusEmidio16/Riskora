package com.riskora.api.service;

import com.riskora.api.dto.CreateDomainRequest;
import com.riskora.api.dto.DomainResponse;
import com.riskora.api.entity.Domain;
import com.riskora.api.entity.Organization;
import com.riskora.api.repository.DomainRepository;
import com.riskora.api.repository.OrganizationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class DomainService {

    private final DomainRepository domainRepository;
    private final OrganizationRepository organizationRepository;

    public DomainService(DomainRepository domainRepository,
                         OrganizationRepository organizationRepository) {
        this.domainRepository = domainRepository;
        this.organizationRepository = organizationRepository;
    }

    @Transactional
    public DomainResponse createDomain(CreateDomainRequest request) {
        // Normalize hostname
        String hostname = request.hostname().toLowerCase().trim();

        // Check if domain already exists
        if (domainRepository.existsByHostname(hostname)) {
            throw new IllegalArgumentException("Domain already exists: " + hostname);
        }

        // For V1, use a default organization (create if needed)
        Organization org = organizationRepository.findById(1L)
                .orElseGet(() -> organizationRepository.save(new Organization("Default")));

        Domain domain = new Domain(hostname, org);
        domain = domainRepository.save(domain);

        return DomainResponse.from(domain);
    }

    @Transactional(readOnly = true)
    public List<DomainResponse> getAllDomains() {
        return domainRepository.findAll().stream()
                .map(DomainResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public DomainResponse getDomainById(Long id) {
        Domain domain = domainRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Domain not found: " + id));
        return DomainResponse.from(domain);
    }
}
