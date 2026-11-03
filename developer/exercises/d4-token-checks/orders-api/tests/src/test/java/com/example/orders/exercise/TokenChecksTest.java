package com.example.orders.exercise;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.orders.security.SecurityConfiguration;
import com.example.testing.jwks.MockIssuer;
import com.example.testing.jwks.MockIssuer.Forgery;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Exercise D4 for orders-api: the decoder must reject every forged token, and the running
 * API must answer 401 for a bad token and 403 for a good token without the role.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TokenChecksTest {
    private static final String AUDIENCE = "orders-api";
    private static final MockIssuer ISSUER = MockIssuer.start();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    @Autowired private JwtDecoder decoder;
    @Autowired private Environment environment;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("ISSUER", ISSUER::issuer);
        registry.add("WORKSHOP_ISSUER", ISSUER::issuer);
        registry.add("SPA_ORIGIN", () -> "https://spa.example.test");
        registry.add("ORDERS_API_CLIENT_SECRET", () -> "not-a-real-secret");
        // Nothing listens on the discard port: no test reaches a downstream service.
        registry.add("INVENTORY_API_URL", () -> "http://127.0.0.1:9");
        registry.add("NOTIFICATIONS_API_URL", () -> "http://127.0.0.1:9");
        registry.add("management.tracing.sampling.probability", () -> "0.0");
    }

    @AfterAll
    static void stop() {
        ISSUER.close();
    }

    @Test
    void theDecoderIsTheOneSecurityConfigurationBuilds() {
        assertThat(decoder).isInstanceOf(NimbusJwtDecoder.class);
        assertThat(SecurityConfiguration.class).hasAnnotation(Configuration.class);
    }

    @Test
    void aValidTokenIsAccepted() {
        var jwt = decoder.decode(ISSUER.token(AUDIENCE));
        assertThat(jwt.getAudience()).containsExactly(AUDIENCE);
    }

    @ParameterizedTest(name = "{0} is rejected")
    @EnumSource(Forgery.class)
    void everyForgedTokenIsRejected(Forgery forgery) {
        String token = ISSUER.forge(forgery, AUDIENCE);
        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
    }

    @ParameterizedTest(name = "{0} gets HTTP 401")
    @EnumSource(Forgery.class)
    void theApiAnswers401ForAForgedToken(Forgery forgery) throws Exception {
        String token = ISSUER.forge(forgery, AUDIENCE, Map.of("realm_access", Map.of("roles", List.of("user"))));
        assertThat(get("/orders", token).statusCode()).isEqualTo(401);
    }

    @Test
    void theApiAnswers401WithoutAToken() throws Exception {
        assertThat(get("/orders", null).statusCode()).isEqualTo(401);
    }

    @Test
    void aReaderCanReadButNotWrite() throws Exception {
        String reader = ISSUER.token(AUDIENCE, Map.of("realm_access", Map.of("roles", List.of("user")),
                "preferred_username", "reader"));
        assertThat(get("/orders", reader).statusCode()).isEqualTo(200);
        var request = HttpRequest.newBuilder(uri("/orders")).header("Authorization", "Bearer " + reader)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"item\":\"widget\",\"quantity\":1}")).build();
        // 403, not 401: the token is valid, the role is missing.
        assertThat(HTTP.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
    }

    private HttpResponse<String> get(String path, String token) throws Exception {
        var builder = HttpRequest.newBuilder(uri(path)).GET();
        if (token != null) builder.header("Authorization", "Bearer " + token);
        return HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + environment.getProperty("local.server.port") + path);
    }
}
