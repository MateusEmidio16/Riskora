package com.riskora.api.dto;

import com.riskora.api.entity.Finding;
import com.riskora.api.entity.Severity;

public record FindingResponse(
        Long id,
        String category,
        Severity severity,
        String title,
        String description,
        String recommendation
) {
    public static FindingResponse from(Finding finding) {
        return new FindingResponse(
                finding.getId(),
                finding.getCategory(),
                finding.getSeverity(),
                finding.getTitle(),
                finding.getDescription(),
                finding.getRecommendation()
        );
    }
}
