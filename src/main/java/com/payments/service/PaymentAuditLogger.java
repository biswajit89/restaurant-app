package com.payments.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.regex.Pattern;

public class PaymentAuditLogger {
    private static final Logger logger = LogManager.getLogger(PaymentAuditLogger.class);
    private static final Pattern SAFE_PATTERN = Pattern.compile("[^a-zA-Z0-9_.-]");

    public static String sanitizeLogContext(String rawInput) {
        if (rawInput == null) return "";
        return SAFE_PATTERN.matcher(rawInput.replace("${", "{_stripped_}")).replaceAll("");
    }

    public void logTransaction(String transactionPayload) {
        // SecureFix Remediation: parameterized log context and input sanitization (CWE-502 / CVE-2021-44228)
        logger.info("Processing transaction context: {}", sanitizeLogContext(transactionPayload));
    }
}
