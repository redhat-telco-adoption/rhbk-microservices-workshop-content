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
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        form.add("subject_token", subject.getTokenValue());
        form.add("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
        form.add("scope", "inventory-api-aud");
        form.add("audience", "inventory-api");
        form.add("client_id", "orders-api");
        form.add("client_secret", clientSecret);
        form.add("requested_token_type", "urn:ietf:params:oauth:token-type:access_token");
        TokenResponse exchanged;
        try {
            exchanged = tokenClient
                    .post().uri(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form).retrieve().body(TokenResponse.class);
        } catch (ResourceAccessException ex) {
            throw new DownstreamFailure(ex.getCause() instanceof java.net.SocketTimeoutException);
        } catch (org.springframework.web.client.RestClientResponseException ex) {
            LOGGER.warn("Token exchange rejected with HTTP status {}", ex.getStatusCode().value());
            throw new DownstreamFailure(false);
        }
        if (exchanged == null || exchanged.access_token() == null || exchanged.access_token().isBlank())
            throw new DownstreamFailure(false);
        var headers = new HttpHeaders();
        headers.setBearerAuth(exchanged.access_token());
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
