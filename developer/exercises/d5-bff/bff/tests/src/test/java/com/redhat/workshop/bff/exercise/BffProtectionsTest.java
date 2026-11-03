package com.redhat.workshop.bff.exercise;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.config.GatewayProperties;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.core.env.Environment;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Exercise D5: the BFF strips browser credentials before relaying to an API, and rejects a
 * cookie-authenticated write that lacks the CSRF token.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class BffProtectionsTest {
    private static final HttpServer KEYCLOAK = discovery();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    @Autowired private GatewayProperties gateway;
    @Autowired private Environment environment;

    /** The BFF reads the issuer's discovery document at startup; serve a minimal one. */
    private static HttpServer discovery() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/realms/workshop/.well-known/openid-configuration", exchange -> {
                String issuer = issuer(server);
                String body = """
                    {"issuer":"%1$s","authorization_endpoint":"%1$s/protocol/openid-connect/auth",
                     "token_endpoint":"%1$s/protocol/openid-connect/token",
                     "jwks_uri":"%1$s/protocol/openid-connect/certs",
                     "end_session_endpoint":"%1$s/protocol/openid-connect/logout",
                     "subject_types_supported":["public"],"response_types_supported":["code"],
                     "id_token_signing_alg_values_supported":["RS256"]}""".formatted(issuer);
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            });
            server.start();
            return server;
        } catch (java.io.IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static String issuer(HttpServer server) {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/realms/workshop";
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("OIDC_ISSUER", () -> issuer(KEYCLOAK));
        registry.add("BFF_CLIENT_SECRET", () -> "not-a-real-secret");
        registry.add("ORDERS_BASE_URL", () -> "http://127.0.0.1:9");
        registry.add("management.tracing.sampling.probability", () -> "0.0");
    }

    @AfterAll
    static void stop() {
        KEYCLOAK.stop(0);
    }

    @Test
    void everyApiRouteStripsBrowserCredentialsAroundTokenRelay() {
        assertThat(gateway.getRoutes()).extracting(RouteDefinition::getId).contains("orders-api", "legacy-api");
        for (RouteDefinition route : gateway.getRoutes()) {
            List<String> filters = route.getFilters().stream().map(BffProtectionsTest::describe).toList();
            int relay = filters.indexOf("TokenRelay");
            assertThat(relay).as("%s relays the session's token", route.getId()).isNotNegative();
            // Before TokenRelay: a browser-supplied Authorization header must never reach the API.
            assertThat(filters.subList(0, relay)).as("%s filters before TokenRelay", route.getId())
                    .contains("RemoveRequestHeader=Authorization", "RemoveRequestHeader=Origin");
            // The SESSION cookie is the BFF's own credential; the API must not see it.
            assertThat(filters).as("%s filters", route.getId()).contains("RemoveRequestHeader=Cookie");
        }
    }

    @Test
    void aWriteWithoutTheCsrfTokenIsForbidden() throws Exception {
        // A cross-site form post carries the session cookie but cannot read XSRF-TOKEN.
        var forged = post(Map.of("Cookie", "SESSION=forged"));
        assertThat(forged.statusCode()).isEqualTo(403);
    }

    @Test
    void aWriteWithAMatchingCsrfTokenPassesTheCsrfCheck() throws Exception {
        // The SPA echoes the cookie in the header; without a session the request is then 401.
        var echoed = post(Map.of("Cookie", "XSRF-TOKEN=echoed-value", "X-XSRF-TOKEN", "echoed-value"));
        assertThat(echoed.statusCode()).isEqualTo(401);
    }

    private HttpResponse<String> post(Map<String, String> headers) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create(
                "http://127.0.0.1:" + environment.getProperty("local.server.port") + "/api/orders"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"item\":\"widget\",\"quantity\":1}"));
        headers.forEach(builder::header);
        return HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String describe(FilterDefinition filter) {
        if (filter.getArgs().isEmpty()) return filter.getName();
        return filter.getName() + "=" + String.join(",", filter.getArgs().values());
    }
}
