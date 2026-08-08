package com.riskora.api.dto;

import jakarta.validation.constraints.NotBlank;

public record CreateDomainRequest(
        @NotBlank(message = "Hostname is required")
        String hostname
) {}
