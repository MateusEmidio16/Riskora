package com.riskora.api.controller;

import com.riskora.api.dto.CreateDomainRequest;
import com.riskora.api.dto.DomainResponse;
import com.riskora.api.service.DomainService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/domains")
public class DomainController {

    private final DomainService domainService;

    public DomainController(DomainService domainService) {
        this.domainService = domainService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public DomainResponse createDomain(@Valid @RequestBody CreateDomainRequest request) {
        return domainService.createDomain(request);
    }

    @GetMapping
    public List<DomainResponse> getAllDomains() {
        return domainService.getAllDomains();
    }

    @GetMapping("/{id}")
    public DomainResponse getDomainById(@PathVariable Long id) {
        return domainService.getDomainById(id);
    }
}
