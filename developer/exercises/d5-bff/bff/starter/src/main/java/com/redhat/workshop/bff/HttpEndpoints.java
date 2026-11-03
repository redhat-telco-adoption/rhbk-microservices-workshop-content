package com.redhat.workshop.bff;

import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
public class HttpEndpoints {
  @GetMapping(value = "/config.json", produces = MediaType.APPLICATION_JSON_VALUE)
  ResponseEntity<Map<String, Object>> config() {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(Map.of("authMode", "bff",
        "issuer", System.getenv().getOrDefault("OIDC_ISSUER", ""),
        "spaClientId", "bff",
        "ordersBaseUrl", "/api/orders",
        "legacyBaseUrl", "/api/legacy",
        "legacyEnabled", Boolean.parseBoolean(System.getenv().getOrDefault("LEGACY_ENABLED", "false"))));
  }

  @GetMapping(value = "/auth/popup-callback", produces = MediaType.TEXT_HTML_VALUE)
  ResponseEntity<Resource> popupCallback() {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore())
        .body(new ClassPathResource("static/auth/popup-callback/index.html"));
  }

  @GetMapping(value = "/auth/logout-callback", produces = MediaType.TEXT_HTML_VALUE)
  ResponseEntity<Resource> logoutCallback() {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore())
        .body(new ClassPathResource("static/auth/logout-callback/index.html"));
  }

  @GetMapping(value = "/csrf", produces = MediaType.APPLICATION_JSON_VALUE)
  Mono<Map<String, String>> csrf(ServerWebExchange exchange) {
    exchange.getResponse().getHeaders().setCacheControl(CacheControl.noStore());
    Mono<CsrfToken> token = exchange.getAttribute(CsrfToken.class.getName());
    if (token == null) return Mono.just(Map.of("error", "csrf_unavailable"));
    return token.map(value -> Map.of("headerName", value.getHeaderName(), "parameterName", value.getParameterName()));
  }
}
