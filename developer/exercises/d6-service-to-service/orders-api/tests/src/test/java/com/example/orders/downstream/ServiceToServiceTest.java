package com.example.orders.downstream;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.testing.jwks.MockIssuer;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.client.RestClient;

/**
 * Exercise D6: orders-api calls inventory-api with an RFC 8693 exchanged token and
 * notifications-api with its own client-credentials token. The user's token reaches neither.
 * A local server plays Keycloak's token endpoint and both downstream APIs.
 */
class ServiceToServiceTest {
    private static final String EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";

    private MockIssuer issuer;
    private HttpServer server;
    private String base;
    private final List<Map<String, String>> tokenRequests = new CopyOnWriteArrayList<>();
    private final List<String> inventoryAuthorization = new CopyOnWriteArrayList<>();
    private final List<String> notificationsAuthorization = new CopyOnWriteArrayList<>();
    private Jwt user;

    @BeforeEach
    void start() throws IOException {
        issuer = MockIssuer.start();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/realms/workshop/protocol/openid-connect/token", exchange -> {
            Map<String, String> form = form(exchange);
            tokenRequests.add(form);
            String token = EXCHANGE.equals(form.get("grant_type")) ? "exchanged-inventory-token"
                    : "client_credentials".equals(form.get("grant_type")) ? "orders-api-machine-token" : null;
            if (token == null) respond(exchange, 400, "{\"error\":\"unsupported_grant_type\"}");
            else respond(exchange, 200, "{\"access_token\":\"" + token + "\",\"token_type\":\"Bearer\","
                    + "\"issued_token_type\":\"" + ACCESS_TOKEN + "\",\"expires_in\":300}");
        });
        server.createContext("/inventory/reserve", exchange -> {
            inventoryAuthorization.add(exchange.getRequestHeaders().getFirst("Authorization"));
            respond(exchange, 200, "{\"reserved\":true}");
        });
        server.createContext("/notify", exchange -> {
            notificationsAuthorization.add(exchange.getRequestHeaders().getFirst("Authorization"));
            respond(exchange, 202, "{\"accepted\":true}");
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        String value = issuer.token("orders-api", Map.of("azp", "spa", "preferred_username", "manager"));
        user = Jwt.withTokenValue(value).header("alg", "RS256").claim("sub", "manager-id")
                .claim("aud", List.of("orders-api")).build();
        // The signed-in user, as Spring Security holds it during POST /orders.
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(user));
    }

    @AfterEach
    void stop() {
        SecurityContextHolder.clearContext();
        server.stop(0);
        issuer.close();
    }

    @Test
    void inventoryReceivesAnExchangedTokenOnEveryRequest() {
        var inventory = new InventoryClient(RestClient.builder(), base + "/realms/workshop", "not-a-real-secret", base);

        assertThat(inventory.reserve(user, "order-1", "widget", 1)).containsEntry("reserved", true);
        inventory.reserve(user, "order-2", "widget", 1);

        assertThat(inventoryAuthorization).containsExactly("Bearer exchanged-inventory-token",
                "Bearer exchanged-inventory-token");
        assertThat(tokenRequests).hasSize(2).allSatisfy(form -> assertThat(form)
                .containsEntry("grant_type", EXCHANGE)
                .containsEntry("subject_token", user.getTokenValue())
                .containsEntry("subject_token_type", ACCESS_TOKEN)
                .containsEntry("requested_token_type", ACCESS_TOKEN)
                .containsEntry("audience", "inventory-api")
                .containsEntry("scope", "inventory-api-aud")
                .containsEntry("client_id", "orders-api"));
    }

    @Test
    void notificationsReceivesTheMachineTokenNotTheUserToken() {
        var registration = ClientRegistration.withRegistrationId("notifications-api")
                .clientId("orders-api").clientSecret("not-a-real-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenUri(base + "/realms/workshop/protocol/openid-connect/token").build();
        var registrations = new InMemoryClientRegistrationRepository(registration);
        var manager = new OAuthClientConfiguration().authorizedClientManager(registrations,
                new InMemoryOAuth2AuthorizedClientService(registrations));
        var notifications = new NotificationsClient(RestClient.builder(), manager, base);

        assertThat(notifications.notifyOrder("order-1")).containsEntry("accepted", true);

        assertThat(notificationsAuthorization).containsExactly("Bearer orders-api-machine-token");
        assertThat(tokenRequests).singleElement().satisfies(form ->
                assertThat(form).containsEntry("grant_type", "client_credentials").doesNotContainKey("subject_token"));
    }

    @Test
    void theUserTokenReachesNoDownstreamApi() {
        inventoryReceivesAnExchangedTokenOnEveryRequest();
        tokenRequests.clear();
        notificationsReceivesTheMachineTokenNotTheUserToken();
        assertThat(inventoryAuthorization).noneMatch(value -> value.contains(user.getTokenValue()));
        assertThat(notificationsAuthorization).noneMatch(value -> value.contains(user.getTokenValue()));
    }

    private static Map<String, String> form(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> form = Arrays.stream(body.split("&")).filter(pair -> !pair.isEmpty())
                .map(pair -> pair.split("=", 2))
                .collect(Collectors.toMap(pair -> URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                        pair -> pair.length > 1 ? URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : ""));
        // Spring sends the client-credentials client as HTTP Basic; record it like a form field.
        String basic = exchange.getRequestHeaders().getFirst("Authorization");
        if (basic != null && basic.startsWith("Basic ")) form.putIfAbsent("client_auth", "basic");
        return form;
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
