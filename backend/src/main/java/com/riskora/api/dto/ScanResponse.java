package com.riskora.api.dto;

import com.riskora.api.entity.Scan;
import com.riskora.api.entity.ScanStatus;

import java.time.LocalDateTime;
import java.util.List;

public record ScanResponse(
        Long id,
        Long domainId,
        String hostname,
        ScanStatus status,
        Integer score,
        LocalDateTime startedAt,
        LocalDateTime finishedAt,
        List<FindingResponse> findings
) {
    public static ScanResponse from(Scan scan, List<FindingResponse> findings) {
        return new ScanResponse(
                scan.getId(),
                scan.getDomain().getId(),
                scan.getDomain().getHostname(),
                scan.getStatus(),
                scan.getScore(),
                scan.getStartedAt(),
                scan.getFinishedAt(),
                findings
        );
    }
}
