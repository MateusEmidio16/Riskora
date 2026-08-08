package com.riskora.api.dto;

import com.riskora.api.entity.Domain;

import java.time.LocalDateTime;

public record DomainResponse(
        Long id,
        String hostname,
        Long organizationId,
        LocalDateTime createdAt
) {
    public static DomainResponse from(Domain domain) {
        return new DomainResponse(
                domain.getId(),
                domain.getHostname(),
                domain.getOrganization().getId(),
                domain.getCreatedAt()
        );
    }
}
