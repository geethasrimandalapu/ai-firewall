package com.aifirewall.gateway;

import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.RestClientException;

@RestControllerAdvice
public class ApiExceptionHandler {

    /** The upstream model failed (bad key, timeout, outage). Never leak the key or raw stack trace. */
    @ExceptionHandler(RestClientException.class)
    public ResponseEntity<Map<String, Object>> upstream(RestClientException e) {
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(Map.of(
                "error", Map.of("type", "upstream_error", "message", "The AI provider request failed")));
    }
}
