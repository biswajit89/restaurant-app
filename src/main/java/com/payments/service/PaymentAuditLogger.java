package com.payments.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.regex.Pattern;

/**
 * Secure Payment Audit Logger
 * Autonomous Security Remediation: Neutralizes CWE-502 / CVE-2021-44228
 * Strips unsafe JNDI format patterns and binds parameters contextually.
 */
public class PaymentAuditLogger {
    private static final Logger logger = LogManager.getLogger(PaymentAuditLogger.class);
    private static final Pattern SAFE_PATTERN = Pattern.compile("[^a-zA-Z0-9_.-]");

    public static String sanitizeLogContext(String rawInput) {
        if (rawInput == null) return "";
        // Strip JNDI message lookup delimiters to prevent outbound arbitrary code loading
        return SAFE_PATTERN.matcher(rawInput.replace("${", "{_neutralized_}")).replaceAll("");
    }

    public void logTransaction(String transactionPayload) {
        String safeContext = sanitizeLogContext(transactionPayload);
        logger.info("Processing payment audit log: {}", safeContext);
    }
}
