package com.riskora.api.scanner;

import com.riskora.api.entity.Finding;
import com.riskora.api.entity.Scan;
import com.riskora.api.entity.Severity;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Phase 13 — HTTP Security Scanner
 * Checks security headers: HSTS, CSP, X-Content-Type-Options,
 * X-Frame-Options, Referrer-Policy, Permissions-Policy
 */
@Component
public class HttpSecurityScanner implements SecurityScanner {

    private static final Map<String, HeaderCheck> SECURITY_HEADERS = Map.of(
            "strict-transport-security", new HeaderCheck(
                    Severity.HIGH,
                    "HSTS (Strict-Transport-Security) header missing",
                    "The server does not send the Strict-Transport-Security header. "
                            + "Without HSTS, users may access your site over insecure HTTP.",
                    "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            ),
            "content-security-policy", new HeaderCheck(
                    Severity.MEDIUM,
                    "Content Security Policy (CSP) header missing",
                    "No Content-Security-Policy header was found. "
                            + "CSP helps prevent cross-site scripting (XSS) and data injection attacks.",
                    "Implement a Content-Security-Policy header appropriate for your application."
            ),
            "x-content-type-options", new HeaderCheck(
                    Severity.MEDIUM,
                    "X-Content-Type-Options header missing",
                    "The X-Content-Type-Options header is not set. "
                            + "This allows browsers to MIME-sniff the content type.",
                    "Add the header: X-Content-Type-Options: nosniff"
            ),
            "x-frame-options", new HeaderCheck(
                    Severity.MEDIUM,
                    "X-Frame-Options header missing",
                    "The X-Frame-Options header is not set. "
                            + "This makes the site vulnerable to clickjacking attacks.",
                    "Add the header: X-Frame-Options: DENY or SAMEORIGIN"
            ),
            "referrer-policy", new HeaderCheck(
                    Severity.LOW,
                    "Referrer-Policy header missing",
                    "No Referrer-Policy header was found. "
                            + "This may leak sensitive URL information to third parties.",
                    "Add the header: Referrer-Policy: strict-origin-when-cross-origin"
            ),
            "permissions-policy", new HeaderCheck(
                    Severity.LOW,
                    "Permissions-Policy header missing",
                    "No Permissions-Policy header was found. "
                            + "This header controls which browser features can be used.",
                    "Add a Permissions-Policy header to restrict browser feature access."
            )
    );

    @Override
    public String getName() {
        return "HTTP Security";
    }

    @Override
    public List<Finding> scan(String hostname, Scan scan) {
        List<Finding> findings = new ArrayList<>();

        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://" + hostname))
                    .timeout(Duration.ofSeconds(15))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request,
                    HttpResponse.BodyHandlers.ofString());

            // Check HTTP to HTTPS redirect
            checkHttpsRedirect(hostname, client, findings, scan);

            // Check each security header
            var headers = response.headers();
            for (var entry : SECURITY_HEADERS.entrySet()) {
                String headerName = entry.getKey();
                HeaderCheck check = entry.getValue();

                if (headers.firstValue(headerName).isEmpty()) {
                    findings.add(new Finding(scan, "HTTP_SECURITY", check.severity(),
                            check.title(), check.description(), check.recommendation()));
                }
            }

        } catch (Exception e) {
            findings.add(new Finding(scan, "HTTP_SECURITY", Severity.HIGH,
                    "HTTPS request failed",
                    "Could not make an HTTPS request to " + hostname + ": " + e.getMessage(),
                    "Ensure your website is accessible via HTTPS."));
        }

        return findings;
    }

    private void checkHttpsRedirect(String hostname, HttpClient client,
                                    List<Finding> findings, Scan scan) {
        try {
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create("http://" + hostname))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();

            // Use a client that does NOT follow redirects
            HttpClient noRedirectClient = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();

            HttpResponse<String> response = noRedirectClient.send(httpRequest,
                    HttpResponse.BodyHandlers.ofString());

            int statusCode = response.statusCode();
            var location = response.headers().firstValue("location");

            if (statusCode >= 300 && statusCode < 400 && location.isPresent()) {
                String loc = location.get();
                if (!loc.startsWith("https://")) {
                    findings.add(new Finding(scan, "HTTP_SECURITY", Severity.HIGH,
                            "HTTP does not redirect to HTTPS",
                            "The HTTP version of the site redirects to " + loc
                                    + " instead of HTTPS.",
                            "Configure HTTP to redirect to HTTPS (301 redirect)."));
                }
            } else if (statusCode == 200) {
                findings.add(new Finding(scan, "HTTP_SECURITY", Severity.HIGH,
                        "HTTP does not redirect to HTTPS",
                        "The site is accessible via plain HTTP without redirecting to HTTPS.",
                        "Configure a 301 redirect from HTTP to HTTPS."));
            }
        } catch (Exception e) {
            // HTTP check failed, not critical
        }
    }

    private record HeaderCheck(Severity severity, String title, String description, String recommendation) {}
}
