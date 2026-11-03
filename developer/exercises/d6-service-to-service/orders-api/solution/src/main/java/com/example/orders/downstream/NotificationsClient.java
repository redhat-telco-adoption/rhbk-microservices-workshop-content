package com.example.orders.downstream;

import java.time.Duration;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

/** Uses a fixed machine principal; no end-user identity is attached to this notification. */
@Component
public final class NotificationsClient {
    private final OAuth2AuthorizedClientManager manager;
    private final RestClient rest;

    public NotificationsClient(RestClient.Builder builder, OAuth2AuthorizedClientManager manager,
                               @Value("${NOTIFICATIONS_API_URL}") String url) {
        this.manager = manager;
        var factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(3));
        factory.setReadTimeout(Duration.ofSeconds(5));
        this.rest = builder.clone().baseUrl(url).requestFactory(factory).build();
    }

    public Map<String, Object> notifyOrder(String orderId) {
        try {
            var authorized = manager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("notifications-api")
                    .principal("orders-api-machine").build());
            if (authorized == null || authorized.getAccessToken() == null) throw new DownstreamFailure(false);
            return rest.post().uri("/notify").contentType(MediaType.APPLICATION_JSON)
                    .headers(headers -> headers.setBearerAuth(authorized.getAccessToken().getTokenValue()))
                    .body(Map.of("orderId", orderId)).retrieve().body(Map.class);
        } catch (ResourceAccessException ex) {
            throw new DownstreamFailure(ex.getCause() instanceof java.net.SocketTimeoutException);
        } catch (org.springframework.web.client.RestClientResponseException ex) {
            throw new DownstreamFailure(false);
        } catch (org.springframework.security.oauth2.core.OAuth2AuthorizationException ex) {
            throw new DownstreamFailure(false);
        }
    }
}
