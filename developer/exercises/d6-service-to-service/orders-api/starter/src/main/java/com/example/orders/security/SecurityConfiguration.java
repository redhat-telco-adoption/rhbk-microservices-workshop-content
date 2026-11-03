package com.example.orders.security;

import java.time.Duration;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import com.example.orders.logging.RequestCompletionFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {
    @Bean NimbusJwtDecoder jwtDecoder(@Value("${ISSUER}") String issuer) {
        var requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(Duration.ofSeconds(3));
        requestFactory.setReadTimeout(Duration.ofSeconds(5));
        var rest = new RestTemplate(requestFactory);
        String jwkSetUri = issuer.replaceAll("/$", "") + "/protocol/openid-connect/certs";
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                .jwsAlgorithm(SignatureAlgorithm.RS256).restOperations(rest).build();
        JwtTimestampValidator timestamps = new JwtTimestampValidator(Duration.ofSeconds(30));
        OAuth2TokenValidator<Jwt> typ = new JwtClaimValidator<String>("typ", "Bearer"::equals);
        OAuth2TokenValidator<Jwt> expiry = new JwtClaimValidator<java.time.Instant>("exp", v -> v != null);
        OAuth2TokenValidator<Jwt> subject = new JwtClaimValidator<String>("sub", v -> v != null && !v.isBlank());
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(timestamps, new JwtIssuerValidator(issuer), typ, expiry, subject, new JwtAudienceValidator()));
        return decoder;
    }

    @Bean SecurityFilterChain api(HttpSecurity http, RequestCompletionFilter completionFilter) throws Exception {
        return http
            .cors(Customizer.withDefaults()).csrf(csrf -> csrf.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a -> a.requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                    .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll().anyRequest().authenticated())
            .exceptionHandling(e -> e.authenticationEntryPoint((request, response, ex) -> {
                request.setAttribute(RequestCompletionFilter.REASON, RequestCompletionFilter.reason(ex));
                response.setHeader("WWW-Authenticate", "Bearer");
                response.sendError(HttpStatus.UNAUTHORIZED.value());
            }).accessDeniedHandler((request, response, ex) -> {
                request.setAttribute(RequestCompletionFilter.REASON, "missing_role");
                response.sendError(HttpStatus.FORBIDDEN.value());
            }))
            .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(new RealmRoleConverter()))
                    .authenticationEntryPoint((request, response, ex) -> {
                        request.setAttribute(RequestCompletionFilter.REASON, RequestCompletionFilter.reason(ex));
                        response.setHeader("WWW-Authenticate", "Bearer");
                        response.sendError(HttpStatus.UNAUTHORIZED.value());
                    }))
            .addFilterBefore(completionFilter, BearerTokenAuthenticationFilter.class)
            .build();
    }

    @Bean CorsConfigurationSource corsConfigurationSource(@Value("${SPA_ORIGIN}") String origin) {
        CorsConfiguration c = new CorsConfiguration();
        c.setAllowedOrigins(List.of(origin)); c.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        c.setAllowedHeaders(List.of("Authorization", "Content-Type", "traceparent", "tracestate"));
        c.setAllowCredentials(false); c.setMaxAge(600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource(); source.registerCorsConfiguration("/**", c); return source;
    }
}
