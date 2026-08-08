package com.riskora.api.controller;

import com.riskora.api.dto.ScanResponse;
import com.riskora.api.service.ScanService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    @PostMapping("/domain/{domainId}")
    @ResponseStatus(HttpStatus.CREATED)
    public ScanResponse runScan(@PathVariable Long domainId) {
        return scanService.runScan(domainId);
    }

    @GetMapping("/{scanId}")
    public ScanResponse getScanById(@PathVariable Long scanId) {
        return scanService.getScanById(scanId);
    }

    @GetMapping("/domain/{domainId}")
    public List<ScanResponse> getScansByDomain(@PathVariable Long domainId) {
        return scanService.getScansByDomainId(domainId);
    }
}
