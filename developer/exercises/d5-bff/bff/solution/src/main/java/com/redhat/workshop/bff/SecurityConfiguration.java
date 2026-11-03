package com.redhat.workshop.bff;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import reactor.core.publisher.Mono;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;

@Configuration
public class SecurityConfiguration {
  @Bean
  SecurityWebFilterChain security(ServerHttpSecurity http, ServerCsrfTokenRepository csrfRepository,
      ReactiveClientRegistrationRepository registrations) {
    var oidcLogout = new OidcClientInitiatedServerLogoutSuccessHandler(registrations);
    oidcLogout.setPostLogoutRedirectUri("{baseUrl}/");
    var authorizationRequests = new DefaultServerOAuth2AuthorizationRequestResolver(registrations);
    authorizationRequests.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
    return http
        .csrf(csrf -> csrf.csrfTokenRepository(csrfRepository)
            .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler()))
        .authorizeExchange(auth -> auth
            .pathMatchers("/", "/index.html", "/assets/**", "/config.json", "/healthz", "/readyz",
                "/actuator/health/**", "/csrf", "/oauth2/**", "/login/**").permitAll()
            .pathMatchers("/api/**").authenticated()
            .pathMatchers("/logout").authenticated()
            .anyExchange().permitAll())
        .exceptionHandling(errors -> errors.authenticationEntryPoint((exchange, ex) -> {
          var response = exchange.getResponse();
          response.setStatusCode(HttpStatus.UNAUTHORIZED);
          response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
          response.getHeaders().setCacheControl("no-store");
          byte[] body = "{\"error\":\"unauthorized\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
          return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
        }))
        .oauth2Login(login -> login.authorizationRequestResolver(authorizationRequests)
            .authorizedClientRepository(authorizedClientRepository()))
        .oauth2Client(client -> {})
        .logout(logout -> logout.logoutUrl("/logout").logoutSuccessHandler(oidcLogout))
        .headers(headers -> headers
            .contentTypeOptions(options -> {})
            .referrerPolicy(policy -> policy.policy(org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
            .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://" + System.getenv().getOrDefault("KEYCLOAK_HOST", "keycloak.invalid"))))
        .build();
  }

  @Bean
  ServerCsrfTokenRepository csrfRepository() {
    CookieServerCsrfTokenRepository repository = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
    repository.setCookieName("XSRF-TOKEN");
    repository.setHeaderName("X-XSRF-TOKEN");
    repository.setCookiePath("/");
    repository.setCookieCustomizer(builder -> builder.secure(true).sameSite("Lax"));
    return repository;
  }

  @Bean
  WebSessionIdResolver sessionIdResolver() {
    CookieWebSessionIdResolver resolver = new CookieWebSessionIdResolver();
    resolver.setCookieName("SESSION");
    resolver.addCookieInitializer(builder -> builder.path("/").httpOnly(true).secure(true).sameSite("Lax"));
    return resolver;
  }

  @Bean
  org.springframework.web.server.WebFilter noStoreSensitiveResponses() {
    return (exchange, chain) -> {
      String path = exchange.getRequest().getPath().value();
      if (path.startsWith("/api/") || path.startsWith("/login/") || path.startsWith("/oauth2/")
          || path.equals("/config.json") || path.equals("/csrf")) {
        exchange.getResponse().getHeaders().setCacheControl("no-store");
      }
      return chain.filter(exchange);
    };
  }

  @Bean
  ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
      ReactiveClientRegistrationRepository registrations, ServerOAuth2AuthorizedClientRepository clients) {
    var manager = new DefaultReactiveOAuth2AuthorizedClientManager(registrations, clients);
    manager.setAuthorizedClientProvider(ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
        .authorizationCode().refreshToken().build());
    return manager;
  }

  @Bean
  ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
    // OAuth clients must follow the same WebSession boundary as the SESSION cookie.
    return new WebSessionServerOAuth2AuthorizedClientRepository();
  }

}
