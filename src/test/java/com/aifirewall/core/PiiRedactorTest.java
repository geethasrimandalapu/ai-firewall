package com.aifirewall.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PiiRedactorTest {

    private final PiiRedactor redactor = new PiiRedactor();

    @Test
    void redactsCommonSensitiveData() {
        var result = redactor.redact(
                "Mail jane@corp.com, card 4111 1111 1111 1111, SSN 123-45-6789, key AKIAABCDEFGHIJKLMNOP");

        assertThat(result.text())
                .contains("[EMAIL_1]", "[CREDIT_CARD_1]", "[SSN_1]", "[API_KEY_1]")
                .doesNotContain("jane@corp.com", "4111", "123-45-6789", "AKIA");
        assertThat(result.findings()).hasSize(4);
    }

    @Test
    void ignoresNumbersThatAreNotRealCards() {
        var result = redactor.redact("Order number 1234567890123 shipped");
        assertThat(result.text()).contains("1234567890123");
    }

    @Test
    void sameValueGetsSameTokenAndCanBeRestored() {
        Map<String, String> vault = new LinkedHashMap<>();
        var r = redactor.redact("a@b.com wrote to c@d.com and a@b.com", vault);

        assertThat(r.text()).isEqualTo("[EMAIL_1] wrote to [EMAIL_2] and [EMAIL_1]");
        assertThat(redactor.restore("Reply to [EMAIL_2]", vault)).isEqualTo("Reply to c@d.com");
    }

    @Test
    void auditMaskNeverExposesFullValue() {
        assertThat(PiiRedactor.mask("secret-value-123")).isEqualTo("se****23");
    }
}
