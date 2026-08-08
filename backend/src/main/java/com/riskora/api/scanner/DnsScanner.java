package com.riskora.api.scanner;

import com.riskora.api.entity.Finding;
import com.riskora.api.entity.Scan;
import com.riskora.api.entity.Severity;
import org.springframework.stereotype.Component;

import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.*;

/**
 * Phase 10 — DNS Scanner
 * Checks: A, AAAA, MX, TXT records, SPF, DMARC
 */
@Component
public class DnsScanner implements SecurityScanner {

    @Override
    public String getName() {
        return "DNS";
    }

    @Override
    public List<Finding> scan(String hostname, Scan scan) {
        List<Finding> findings = new ArrayList<>();

        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            DirContext ctx = new InitialDirContext(env);

            // Check A records
            checkRecord(ctx, hostname, "A", findings, scan);

            // Check AAAA records
            checkRecord(ctx, hostname, "AAAA", findings, scan);

            // Check MX records
            checkMxRecords(ctx, hostname, findings, scan);

            // Check TXT records and SPF
            checkTxtAndSpf(ctx, hostname, findings, scan);

            // Check DMARC
            checkDmarc(ctx, hostname, findings, scan);

            ctx.close();
        } catch (NamingException e) {
            findings.add(new Finding(scan, "DNS", Severity.HIGH, "DNS resolution failed",
                    "Could not resolve DNS for " + hostname + ": " + e.getMessage(),
                    "Verify that the domain exists and DNS is properly configured."));
        }

        return findings;
    }

    private void checkRecord(DirContext ctx, String hostname, String type,
                             List<Finding> findings, Scan scan) {
        try {
            Attributes attrs = ctx.getAttributes(hostname, new String[]{type});
            Attribute attr = attrs.get(type);
            if (attr == null || attr.size() == 0) {
                if ("AAAA".equals(type)) {
                    findings.add(new Finding(scan, "DNS", Severity.LOW,
                            "No IPv6 (AAAA) records found",
                            "The domain does not have AAAA records for IPv6 connectivity.",
                            "Consider adding AAAA records for IPv6 support."));
                }
            }
        } catch (NamingException e) {
            if ("A".equals(type)) {
                findings.add(new Finding(scan, "DNS", Severity.HIGH,
                        "No A records found",
                        "The domain does not resolve to any IPv4 address.",
                        "Configure A records in your DNS settings."));
            }
        }
    }

    private void checkMxRecords(DirContext ctx, String hostname,
                                List<Finding> findings, Scan scan) {
        try {
            Attributes attrs = ctx.getAttributes(hostname, new String[]{"MX"});
            Attribute attr = attrs.get("MX");
            if (attr == null || attr.size() == 0) {
                findings.add(new Finding(scan, "EMAIL_SECURITY", Severity.MEDIUM,
                        "No MX records found",
                        "The domain does not have MX records configured for email.",
                        "If you use email, configure MX records pointing to your mail server."));
            }
        } catch (NamingException e) {
            // MX not found is not critical
        }
    }

    private void checkTxtAndSpf(DirContext ctx, String hostname,
                                List<Finding> findings, Scan scan) {
        try {
            Attributes attrs = ctx.getAttributes(hostname, new String[]{"TXT"});
            Attribute attr = attrs.get("TXT");
            boolean spfFound = false;

            if (attr != null) {
                for (int i = 0; i < attr.size(); i++) {
                    String record = attr.get(i).toString();
                    if (record.contains("v=spf1")) {
                        spfFound = true;
                    }
                }
            }

            if (!spfFound) {
                findings.add(new Finding(scan, "EMAIL_SECURITY", Severity.HIGH,
                        "SPF record not configured",
                        "No SPF (Sender Policy Framework) record was found. "
                                + "This means anyone can send emails pretending to be from your domain.",
                        "Add a TXT record with an SPF policy, e.g.: v=spf1 include:_spf.google.com ~all"));
            }
        } catch (NamingException e) {
            findings.add(new Finding(scan, "EMAIL_SECURITY", Severity.HIGH,
                    "SPF record not configured",
                    "Could not find TXT records for SPF verification.",
                    "Add a TXT record with an SPF policy."));
        }
    }

    private void checkDmarc(DirContext ctx, String hostname,
                            List<Finding> findings, Scan scan) {
        try {
            String dmarcDomain = "_dmarc." + hostname;
            Attributes attrs = ctx.getAttributes(dmarcDomain, new String[]{"TXT"});
            Attribute attr = attrs.get("TXT");
            boolean dmarcFound = false;

            if (attr != null) {
                for (int i = 0; i < attr.size(); i++) {
                    String record = attr.get(i).toString();
                    if (record.contains("v=DMARC1")) {
                        dmarcFound = true;
                    }
                }
            }

            if (!dmarcFound) {
                findings.add(new Finding(scan, "EMAIL_SECURITY", Severity.HIGH,
                        "DMARC not configured",
                        "No DMARC policy was found at _dmarc." + hostname + ". "
                                + "Without DMARC, your domain is vulnerable to email spoofing.",
                        "Add a DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@" + hostname));
            }
        } catch (NamingException e) {
            findings.add(new Finding(scan, "EMAIL_SECURITY", Severity.HIGH,
                    "DMARC not configured",
                    "The domain does not publish a DMARC policy at _dmarc." + hostname + ".",
                    "Configure a DMARC record to protect against email spoofing."));
        }
    }
}
