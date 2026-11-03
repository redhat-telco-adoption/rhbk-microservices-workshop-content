package com.redhat.workshop.bff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

class AuthorizedClientRefreshFilterTest {
  private ReactiveOAuth2AuthorizedClientManager manager;
  private AuthorizedClientRefreshFilter filter;
  private Authentication authentication;

  @BeforeEach
  void setUp() {
    manager = mock(ReactiveOAuth2AuthorizedClientManager.class);
    filter = new AuthorizedClientRefreshFilter(manager);
    authentication = mock(Authentication.class);
  }

  @Test
  void anonymousApiRequestExecutesTheRemainingChainOnceWithoutAuthorization() {
    AtomicInteger downstream = new AtomicInteger();
    GatewayFilterChain chain = ignored -> {
      downstream.incrementAndGet();
      return Mono.empty();
    };

    filter.filter(exchange("/api/orders", Mono.empty(), "anonymous"), chain).block();

    assertEquals(1, downstream.get());
    verify(manager, never()).authorize(any(OAuth2AuthorizeRequest.class));
  }

  @Test
  void authorizedRequestWaitsForAuthorizedClientAndExecutesTheChainOnce() {
    when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
        .thenReturn(Mono.just(mock(OAuth2AuthorizedClient.class)));
    AtomicInteger downstream = new AtomicInteger();
    GatewayFilterChain chain = ignored -> {
      downstream.incrementAndGet();
      return Mono.empty();
    };

    filter.filter(exchange("/api/orders", Mono.just(authentication), "alice-session"), chain).block();

    assertEquals(1, downstream.get());
    verify(manager).authorize(any(OAuth2AuthorizeRequest.class));
  }

  @Test
  void concurrentRequestsInOneSessionShareAuthorizationButEachExecuteTheirOwnChain() {
    when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenReturn(
        Mono.delay(Duration.ofMillis(20)).thenReturn(mock(OAuth2AuthorizedClient.class)));
    AtomicInteger downstream = new AtomicInteger();
    GatewayFilterChain chain = ignored -> {
      downstream.incrementAndGet();
      return Mono.empty();
    };
    ServerWebExchange first = exchange("/api/orders", Mono.just(authentication), "alice-session");
    ServerWebExchange second = exchange("/api/orders/42", Mono.just(authentication), "alice-session");

    Mono.when(filter.filter(first, chain), filter.filter(second, chain)).block();

    assertEquals(2, downstream.get());
    verify(manager).authorize(any(OAuth2AuthorizeRequest.class));
  }

  @Test
  void distinctSessionsDoNotShareAuthorizationWork() {
    when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenReturn(
        Mono.delay(Duration.ofMillis(20)).thenReturn(mock(OAuth2AuthorizedClient.class)));
    AtomicInteger downstream = new AtomicInteger();
    GatewayFilterChain chain = ignored -> {
      downstream.incrementAndGet();
      return Mono.empty();
    };

    Mono.when(
        filter.filter(exchange("/api/orders", Mono.just(authentication), "alice-session"), chain),
        filter.filter(exchange("/api/orders", Mono.just(authentication), "bob-session"), chain))
        .block();

    assertEquals(2, downstream.get());
    verify(manager, org.mockito.Mockito.times(2)).authorize(any(OAuth2AuthorizeRequest.class));
  }

  @Test
  void failedAuthorizationPreventsDownstreamWork() {
    when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
        .thenReturn(Mono.error(new IllegalStateException("refresh rejected")));
    AtomicInteger downstream = new AtomicInteger();
    GatewayFilterChain chain = ignored -> {
      downstream.incrementAndGet();
      return Mono.empty();
    };

    assertThrows(IllegalStateException.class,
        () -> filter.filter(exchange("/api/orders", Mono.just(authentication), "alice-session"), chain).block());
    assertEquals(0, downstream.get());
  }

  @Test
  void nonApiRequestDoesNotAuthorizeAndExecutesOnce() {
    AtomicInteger downstream = new AtomicInteger();
    GatewayFilterChain chain = ignored -> {
      downstream.incrementAndGet();
      return Mono.empty();
    };

    filter.filter(exchange("/healthz", Mono.just(authentication), "alice-session"), chain).block();

    assertEquals(1, downstream.get());
    verify(manager, never()).authorize(any(OAuth2AuthorizeRequest.class));
  }

  private static ServerWebExchange exchange(String path, Mono<? extends Principal> principal, String sessionId) {
    ServerWebExchange exchange = mock(ServerWebExchange.class);
    ServerHttpRequest request = mock(ServerHttpRequest.class);
    WebSession session = mock(WebSession.class);
    when(request.getPath()).thenReturn(RequestPath.parse(path, ""));
    when(exchange.getRequest()).thenReturn(request);
    when(exchange.getPrincipal()).thenReturn(principal.map(value -> (Principal) value));
    when(exchange.getSession()).thenReturn(Mono.just(session));
    when(session.getId()).thenReturn(sessionId);
    return exchange;
  }
}
