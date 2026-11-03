package com.example.orders.downstream;

import java.time.Duration;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.jwt.Jwt;

/** Exchanges each incoming user token separately so inventory sees the least-privilege audience. */
@Component
public final class InventoryClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(InventoryClient.class);
    private final RestClient rest;
    private final RestClient tokenClient;
    private final String tokenEndpoint;
    private final String clientSecret;

    public InventoryClient(RestClient.Builder builder,
                           @Value("${WORKSHOP_ISSUER}") String issuer,
                           @Value("${ORDERS_API_CLIENT_SECRET}") String clientSecret,
                           @Value("${INVENTORY_API_URL}") String inventoryUrl) {
        this.tokenEndpoint = issuer.replaceAll("/$", "") + "/protocol/openid-connect/token";
        this.clientSecret = clientSecret;
        var factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(3));
        factory.setReadTimeout(Duration.ofSeconds(5));
        this.rest = builder.clone().requestFactory(factory).baseUrl(inventoryUrl).build();
        this.tokenClient = builder.clone().requestFactory(requestFactory()).build();
    }

    public Map<String, Object> reserve(Jwt subject, String orderId, String item, int quantity) {
        // ANTI-PATTERN: inventory-api rejects this token because its audience is orders-api.
        // Exercise D6: exchange subject's token at tokenEndpoint (RFC 8693 token exchange) for an
        // inventory-api token, and send only the exchanged token. Never cache or return it.
        var headers = new HttpHeaders();
        headers.setBearerAuth(subject.getTokenValue());
        headers.setContentType(MediaType.APPLICATION_JSON);
        try {
            return rest.post().uri("/inventory/reserve")
                    .body(Map.of("orderId", orderId, "item", item, "quantity", quantity))
                    .headers(h -> h.addAll(headers)).retrieve().body(Map.class);
        } catch (ResourceAccessException ex) {
            throw new DownstreamFailure(ex.getCause() instanceof java.net.SocketTimeoutException);
        } catch (org.springframework.web.client.RestClientResponseException ex) {
            LOGGER.warn("Inventory reservation rejected with HTTP status {}", ex.getStatusCode().value());
            throw new DownstreamFailure(false);
        }
    }

    private static SimpleClientHttpRequestFactory requestFactory() {
        var factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(3));
        factory.setReadTimeout(Duration.ofSeconds(5));
        return factory;
    }
    private record TokenResponse(String access_token, String token_type, String issued_token_type, Integer expires_in) {}
}
