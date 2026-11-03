package com.redhat.workshop.bff;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import net.logstash.logback.argument.StructuredArguments;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import io.opentelemetry.api.trace.Span;
import reactor.core.publisher.Mono;

@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class RequestCompletionLogFilter implements WebFilter {
  private static final Logger log = LoggerFactory.getLogger(RequestCompletionLogFilter.class);
  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    String path = exchange.getRequest().getPath().value();
    if (!path.startsWith("/api/")) return chain.filter(exchange);
    long started = System.nanoTime();
    return chain.filter(exchange).then(logCompletion(exchange, started))
        .onErrorResume(error -> logCompletion(exchange, started).then(Mono.error(error)));
  }

  private Mono<Void> logCompletion(ServerWebExchange exchange, long started) {
    return ReactiveSecurityContextHolder.getContext()
        .map(context -> Optional.ofNullable(context.getAuthentication()))
        .defaultIfEmpty(Optional.empty())
        .doOnNext(value -> emit(exchange, started, value.orElse(null)))
        .then();
  }

  private void emit(ServerWebExchange exchange, long started, Authentication authentication) {
    String subject = null;
    String username = null;
    String clientId = null;
    List<String> roles = List.of();
    if (authentication instanceof OAuth2AuthenticationToken oauth && oauth.getPrincipal() instanceof OidcUser user) {
      subject = user.getSubject();
      username = user.getClaimAsString("preferred_username");
      clientId = user.getClaimAsString("azp");
      Map<String, Object> realm = user.getClaim("realm_access");
      if (realm != null && realm.get("roles") instanceof List<?> claimedRoles) {
        roles = claimedRoles.stream().filter(String.class::isInstance).map(String.class::cast).toList();
      }
    }
    var spanContext = Span.current().getSpanContext();
    String traceId = spanContext.isValid() ? spanContext.getTraceId() : null;
    String spanId = spanContext.isValid() ? spanContext.getSpanId() : null;
    int status = exchange.getResponse().getStatusCode() == null ? 200 : exchange.getResponse().getStatusCode().value();
    String reason = status == 401 ? "missing_token" : status == 403 ? "missing_role" : null;
    var event = log.atLevel(status >= 400 ? org.slf4j.event.Level.WARN : org.slf4j.event.Level.INFO);
    event.addKeyValue("timestamp", java.time.Instant.now().toString())
        .addKeyValue("level", status >= 400 ? "WARN" : "INFO")
        .addKeyValue("decision", status >= 400 ? "deny" : "allow")
        .addKeyValue("span_id", spanId).log("request_complete",
        StructuredArguments.keyValue("event", "request_complete"),
        StructuredArguments.keyValue("service", "bff"),
        StructuredArguments.keyValue("method", exchange.getRequest().getMethod().name()),
        StructuredArguments.keyValue("path", exchange.getRequest().getPath().value()),
        StructuredArguments.keyValue("status", status),
        StructuredArguments.keyValue("subject", subject),
        StructuredArguments.keyValue("username", username),
        StructuredArguments.keyValue("client_id", clientId),
        StructuredArguments.keyValue("roles", roles),
        StructuredArguments.keyValue("reason", reason),
        StructuredArguments.keyValue("trace_id", traceId),
        StructuredArguments.keyValue("duration_ms", (System.nanoTime() - started) / 1_000_000));
  }
}
