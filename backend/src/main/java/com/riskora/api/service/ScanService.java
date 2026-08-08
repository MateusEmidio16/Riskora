package com.riskora.api.service;

import com.riskora.api.dto.FindingResponse;
import com.riskora.api.dto.ScanResponse;
import com.riskora.api.entity.*;
import com.riskora.api.repository.DomainRepository;
import com.riskora.api.repository.FindingRepository;
import com.riskora.api.repository.ScanRepository;
import com.riskora.api.scanner.ScoreEngine;
import com.riskora.api.scanner.SecurityScanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Phase 9 — Scan Service
 * Orchestrates all scanners, stores results, calculates score.
 */
@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final DomainRepository domainRepository;
    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final List<SecurityScanner> scanners;
    private final ScoreEngine scoreEngine;

    public ScanService(DomainRepository domainRepository,
                       ScanRepository scanRepository,
                       FindingRepository findingRepository,
                       List<SecurityScanner> scanners,
                       ScoreEngine scoreEngine) {
        this.domainRepository = domainRepository;
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
        this.scanners = scanners;
        this.scoreEngine = scoreEngine;
    }

    @Transactional
    public ScanResponse runScan(Long domainId) {
        Domain domain = domainRepository.findById(domainId)
                .orElseThrow(() -> new IllegalArgumentException("Domain not found: " + domainId));

        // Create scan record
        Scan scan = new Scan(domain);
        scan.setStatus(ScanStatus.RUNNING);
        scan.setStartedAt(LocalDateTime.now());
        scan = scanRepository.save(scan);

        List<Finding> allFindings = new ArrayList<>();

        // Run each scanner
        for (SecurityScanner scanner : scanners) {
            try {
                log.info("Running {} scanner for {}", scanner.getName(), domain.getHostname());
                List<Finding> findings = scanner.scan(domain.getHostname(), scan);
                allFindings.addAll(findings);
                log.info("{} scanner found {} findings", scanner.getName(), findings.size());
            } catch (Exception e) {
                log.error("Scanner {} failed for {}: {}", scanner.getName(),
                        domain.getHostname(), e.getMessage());
                allFindings.add(new Finding(scan, scanner.getName(), Severity.HIGH,
                        scanner.getName() + " scanner failed",
                        "An error occurred during scanning: " + e.getMessage(),
                        "This may be a temporary issue. Try scanning again."));
            }
        }

        // Save all findings
        findingRepository.saveAll(allFindings);

        // Calculate score
        int score = scoreEngine.calculateScore(allFindings);

        // Update scan
        scan.setStatus(ScanStatus.COMPLETED);
        scan.setScore(score);
        scan.setFinishedAt(LocalDateTime.now());
        scan = scanRepository.save(scan);

        // Build response
        List<FindingResponse> findingResponses = allFindings.stream()
                .map(FindingResponse::from)
                .toList();

        return ScanResponse.from(scan, findingResponses);
    }

    @Transactional(readOnly = true)
    public ScanResponse getScanById(Long scanId) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found: " + scanId));

        List<FindingResponse> findings = findingRepository.findByScanId(scanId).stream()
                .map(FindingResponse::from)
                .toList();

        return ScanResponse.from(scan, findings);
    }

    @Transactional(readOnly = true)
    public List<ScanResponse> getScansByDomainId(Long domainId) {
        return scanRepository.findByDomainIdOrderByCreatedAtDesc(domainId).stream()
                .map(scan -> {
                    List<FindingResponse> findings = findingRepository.findByScanId(scan.getId())
                            .stream().map(FindingResponse::from).toList();
                    return ScanResponse.from(scan, findings);
                })
                .toList();
    }
}
