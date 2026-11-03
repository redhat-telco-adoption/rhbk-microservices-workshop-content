package com.redhat.workshop.bff;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Optional;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/** Refreshes a session's authorized client before TokenRelay and serializes refresh-token rotation. */
@Component
public class AuthorizedClientRefreshFilter implements GlobalFilter, Ordered {
  private final ReactiveOAuth2AuthorizedClientManager manager;
  private final ConcurrentHashMap<String, Mono<?>> refreshes = new ConcurrentHashMap<>();

  public AuthorizedClientRefreshFilter(ReactiveOAuth2AuthorizedClientManager manager) {
    this.manager = manager;
  }

  @Override public int getOrder() { return -100; }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    String path = exchange.getRequest().getPath().value();
    if (!(path.equals("/api/orders") || path.startsWith("/api/orders/")
        || path.startsWith("/api/legacy/"))) return chain.filter(exchange);
    Mono<Optional<Authentication>> principal = exchange.getPrincipal().ofType(Authentication.class)
        .map(Optional::of).defaultIfEmpty(Optional.empty()).cache();
    return principal.flatMap(found -> {
      if (found.isEmpty()) return chain.filter(exchange);
      Authentication authentication = found.get();
      return exchange.getSession().flatMap(session -> {
          String key = session.getId();
          Mono<?> current = Mono.defer(() -> manager.authorize(OAuth2AuthorizeRequest
                  .withClientRegistrationId("keycloak").principal(authentication)
                  .attribute(ServerWebExchange.class.getName(), exchange).build()))
              .switchIfEmpty(Mono.error(new IllegalStateException("No authorized client is available for this session.")))
              .cache();
          Mono<?> pending = refreshes.putIfAbsent(key, current);
          Mono<?> serialized = pending == null ? current : pending;
          return serialized.thenReturn(authentication).doFinally(signal -> {
            if (pending == null) refreshes.remove(key, current);
          });
        }).then(Mono.defer(() -> chain.filter(exchange)));
    });
  }
}
