package com.riskora.api.scanner;

import com.riskora.api.entity.Finding;
import com.riskora.api.entity.Scan;
import com.riskora.api.entity.Severity;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Phase 12 — TLS Scanner
 * Checks: HTTPS, certificate validity, expiration, hostname, TLS version
 */
@Component
public class TlsScanner implements SecurityScanner {

    @Override
    public String getName() {
        return "TLS";
    }

    @Override
    public List<Finding> scan(String hostname, Scan scan) {
        List<Finding> findings = new ArrayList<>();

        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            // Use a trust manager that accepts all certificates for analysis
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
            };
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket(hostname, 443);
            socket.setSoTimeout(10000);
            socket.startHandshake();

            SSLSession session = socket.getSession();

            // Check TLS version
            String protocol = session.getProtocol();
            checkTlsVersion(protocol, findings, scan);

            // Check certificate
            Certificate[] certs = session.getPeerCertificates();
            if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                X509Certificate cert = (X509Certificate) certs[0];
                checkCertificateValidity(cert, findings, scan);
                checkCertificateExpiration(cert, findings, scan, hostname);
                checkCertificateHostname(cert, hostname, findings, scan);
            }

            socket.close();

        } catch (javax.net.ssl.SSLHandshakeException e) {
            findings.add(new Finding(scan, "TLS", Severity.CRITICAL,
                    "SSL/TLS handshake failed",
                    "Could not establish a secure connection to " + hostname + ": " + e.getMessage(),
                    "Ensure your server has a valid SSL/TLS certificate installed."));
        } catch (java.net.ConnectException e) {
            findings.add(new Finding(scan, "TLS", Severity.CRITICAL,
                    "HTTPS not available",
                    "Could not connect to " + hostname + " on port 443. HTTPS is not available.",
                    "Enable HTTPS on your server with a valid SSL certificate."));
        } catch (Exception e) {
            findings.add(new Finding(scan, "TLS", Severity.HIGH,
                    "TLS check failed",
                    "An error occurred while checking TLS: " + e.getMessage(),
                    "Ensure your server supports HTTPS connections."));
        }

        return findings;
    }

    private void checkTlsVersion(String protocol, List<Finding> findings, Scan scan) {
        if ("TLSv1".equals(protocol) || "TLSv1.1".equals(protocol)) {
            findings.add(new Finding(scan, "TLS", Severity.CRITICAL,
                    "Outdated TLS version: " + protocol,
                    "The server is using " + protocol + " which is deprecated and insecure.",
                    "Upgrade to TLS 1.2 or TLS 1.3."));
        } else if ("TLSv1.2".equals(protocol)) {
            // TLS 1.2 is acceptable but 1.3 is preferred
        }
        // TLS 1.3 is ideal — no finding needed
    }

    private void checkCertificateValidity(X509Certificate cert, List<Finding> findings, Scan scan) {
        try {
            cert.checkValidity();
        } catch (java.security.cert.CertificateExpiredException e) {
            findings.add(new Finding(scan, "TLS", Severity.CRITICAL,
                    "SSL certificate has expired",
                    "The SSL certificate expired on " + cert.getNotAfter() + ".",
                    "Renew the SSL certificate immediately."));
        } catch (java.security.cert.CertificateNotYetValidException e) {
            findings.add(new Finding(scan, "TLS", Severity.CRITICAL,
                    "SSL certificate is not yet valid",
                    "The SSL certificate is not valid until " + cert.getNotBefore() + ".",
                    "Check your certificate's validity period."));
        }
    }

    private void checkCertificateExpiration(X509Certificate cert, List<Finding> findings,
                                           Scan scan, String hostname) {
        Date expiryDate = cert.getNotAfter();
        long daysUntilExpiry = ChronoUnit.DAYS.between(Instant.now(), expiryDate.toInstant());

        if (daysUntilExpiry <= 7) {
            findings.add(new Finding(scan, "TLS", Severity.CRITICAL,
                    "Certificate expires in " + daysUntilExpiry + " days",
                    "The SSL certificate for " + hostname + " expires on " + expiryDate + ".",
                    "Renew the certificate immediately to avoid service disruption."));
        } else if (daysUntilExpiry <= 30) {
            findings.add(new Finding(scan, "TLS", Severity.HIGH,
                    "Certificate expires in " + daysUntilExpiry + " days",
                    "The SSL certificate for " + hostname + " expires on " + expiryDate + ".",
                    "Renew the certificate soon."));
        } else if (daysUntilExpiry <= 90) {
            findings.add(new Finding(scan, "TLS", Severity.MEDIUM,
                    "Certificate expires in " + daysUntilExpiry + " days",
                    "The SSL certificate for " + hostname + " expires on " + expiryDate + ".",
                    "Plan to renew the certificate before it expires."));
        }
    }

    private void checkCertificateHostname(X509Certificate cert, String hostname,
                                          List<Finding> findings, Scan scan) {
        try {
            // Check Subject Alternative Names
            var sans = cert.getSubjectAlternativeNames();
            boolean hostnameMatch = false;

            if (sans != null) {
                for (var san : sans) {
                    if (san.size() >= 2) {
                        String value = san.get(1).toString();
                        if (hostname.equals(value) || matchesWildcard(value, hostname)) {
                            hostnameMatch = true;
                            break;
                        }
                    }
                }
            }

            // Fallback: check CN
            if (!hostnameMatch) {
                String cn = cert.getSubjectX500Principal().getName();
                if (cn.contains("CN=" + hostname)) {
                    hostnameMatch = true;
                }
            }

            if (!hostnameMatch) {
                findings.add(new Finding(scan, "TLS", Severity.HIGH,
                        "Certificate hostname mismatch",
                        "The SSL certificate does not match the hostname " + hostname + ".",
                        "Ensure the certificate covers the correct domain name."));
            }
        } catch (Exception e) {
            // Could not verify hostname
        }
    }

    private boolean matchesWildcard(String pattern, String hostname) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1);
            int dotIndex = hostname.indexOf('.');
            if (dotIndex >= 0) {
                return hostname.substring(dotIndex).equals(suffix);
            }
        }
        return false;
    }
}
