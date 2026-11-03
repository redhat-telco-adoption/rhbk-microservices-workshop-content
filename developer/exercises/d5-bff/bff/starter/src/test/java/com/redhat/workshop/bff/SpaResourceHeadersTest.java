package com.redhat.workshop.bff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

class SpaResourceHeadersTest {
  @Test
  void documentHistoryAndAssetResponsesSetTheSecurityHeaders() {
    var filter = new GatewayConfiguration().spaResources();
    for (String path : new String[] {"/", "/orders/history", "/assets/app.js"}) {
      ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get(path).build());

      filter.filter(exchange, ignored -> Mono.empty()).block();

      HttpHeaders headers = exchange.getResponse().getHeaders();
      assertEquals("nosniff", headers.getFirst("X-Content-Type-Options"), path);
      assertEquals("DENY", headers.getFirst("X-Frame-Options"), path);
      assertEquals("strict-origin-when-cross-origin", headers.getFirst("Referrer-Policy"), path);
      assertNotNull(headers.getFirst("Content-Security-Policy"), path);
      assertEquals("no-store", headers.getCacheControl(), path);
    }
  }
}
