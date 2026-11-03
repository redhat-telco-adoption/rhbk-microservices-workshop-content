package com.example.orders.downstream;

import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class DownstreamErrorHandler {
    @ExceptionHandler(DownstreamFailure.class)
    public ResponseEntity<Map<String, String>> downstream(DownstreamFailure failure) {
        return ResponseEntity.status(failure.timeout() ? HttpStatus.GATEWAY_TIMEOUT : HttpStatus.BAD_GATEWAY)
                .body(Map.of("error", failure.timeout() ? "downstream_timeout" : "downstream_unavailable"));
    }
}
