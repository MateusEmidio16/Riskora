package com.riskora.api.scanner;

import com.riskora.api.entity.Finding;
import com.riskora.api.entity.Scan;

import java.util.List;

/**
 * Interface for all security scanners.
 * Each scanner produces a list of findings for a given domain.
 */
public interface SecurityScanner {

    /**
     * Run the scanner against the given hostname.
     * @param hostname the domain to scan
     * @param scan the parent scan entity
     * @return list of findings
     */
    List<Finding> scan(String hostname, Scan scan);

    /**
     * @return the name of this scanner for logging
     */
    String getName();
}
