package com.riskora.api.scanner;

import com.riskora.api.entity.Finding;
import com.riskora.api.entity.Severity;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Phase 14 — Score Engine
 * Calculates a 0-100 security score based on findings.
 */
@Component
public class ScoreEngine {

    private static final int STARTING_SCORE = 100;
    private static final int MIN_SCORE = 0;

    public int calculateScore(List<Finding> findings) {
        int score = STARTING_SCORE;

        for (Finding finding : findings) {
            score -= getDeduction(finding.getSeverity());
        }

        return Math.max(score, MIN_SCORE);
    }

    private int getDeduction(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 25;
            case HIGH -> 15;
            case MEDIUM -> 8;
            case LOW -> 3;
            case INFO -> 0;
        };
    }
}
