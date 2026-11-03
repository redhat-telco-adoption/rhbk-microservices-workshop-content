package com.redhat.workshop.bff;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.ApplicationRunner;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.web.server.WebFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.MediaTypeFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import java.time.Duration;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

@Configuration
public class GatewayConfiguration {
  private static final org.slf4j.Logger log = LoggerFactory.getLogger(GatewayConfiguration.class);

  @Bean
  ApplicationRunner requireConfiguredGatewayRoutes(RouteLocator routes) {
    return args -> {
      var ids = routes.getRoutes().map(route -> route.getId()).collectList().block(Duration.ofSeconds(10));
      if (ids == null || !ids.containsAll(java.util.List.of("orders-api", "legacy-api"))) {
        throw new IllegalStateException("Required BFF API routes are not configured.");
      }
      log.info("BFF API routes are configured: {}", ids);
    };
  }

  @Bean
  WebFilter disabledLegacy() {
    return (exchange, chain) -> {
      if (!Boolean.parseBoolean(System.getenv().getOrDefault("LEGACY_ENABLED", "false"))
          && exchange.getRequest().getPath().value().startsWith("/api/legacy/")) {
        exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
        exchange.getResponse().getHeaders().setCacheControl("no-store");
        return exchange.getResponse().setComplete();
      }
      return chain.filter(exchange);
    };
  }

  @Bean
  @org.springframework.core.annotation.Order(Ordered.HIGHEST_PRECEDENCE + 20)
  WebFilter spaResources() {
    return (exchange, chain) -> {
      String path = exchange.getRequest().getPath().value();
      if (path.startsWith("/api/") || path.startsWith("/oauth2/") || path.startsWith("/login/")
          || path.startsWith("/actuator/") || path.equals("/config.json") || path.equals("/csrf")
          || path.equals("/logout") || path.startsWith("/auth/")) {
        return chain.filter(exchange);
      }
      String relative = path.equals("/") ? "index.html" : path.startsWith("/assets/") ? path.substring(1)
          : path.contains(".") ? null : "index.html";
      if (relative == null || relative.contains("..")) return chain.filter(exchange);
      Resource resource = new ClassPathResource("static/" + relative);
      if (!resource.exists() || !resource.isReadable()) return chain.filter(exchange);
      var response = exchange.getResponse();
      response.getHeaders().setCacheControl(org.springframework.http.CacheControl.noStore());
      // This early resource filter writes the response before Spring Security's header
      // writers run, so apply the same document protections here explicitly.
      response.getHeaders().set("X-Content-Type-Options", "nosniff");
      response.getHeaders().set("X-Frame-Options", "DENY");
      response.getHeaders().set("Referrer-Policy", "strict-origin-when-cross-origin");
      response.getHeaders().set("Content-Security-Policy", "default-src 'self'; script-src 'self'; "
          + "style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
          + "base-uri 'self'; form-action 'self' https://"
          + System.getenv().getOrDefault("KEYCLOAK_HOST", "keycloak.invalid"));
      response.getHeaders().setContentType(MediaTypeFactory.getMediaType(resource).orElse(MediaType.APPLICATION_OCTET_STREAM));
      return DataBufferUtils.read(resource, response.bufferFactory(), 8192)
          .as(response::writeWith);
    };
  }
}
