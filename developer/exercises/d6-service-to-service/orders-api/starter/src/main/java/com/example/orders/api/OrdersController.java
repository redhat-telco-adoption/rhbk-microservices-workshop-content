package com.example.orders.api;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import com.example.orders.downstream.InventoryClient;
import com.example.orders.downstream.NotificationsClient;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Size;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.beans.factory.annotation.Autowired;

@RestController
public class OrdersController {
    public record OrderRequest(@NotBlank @Size(max = 120) String item, @Min(1) @Max(1000) int quantity) {}
    private final InventoryClient inventory;
    private final NotificationsClient notifications;

    @Autowired
    public OrdersController(InventoryClient inventory, NotificationsClient notifications) {
        this.inventory = inventory;
        this.notifications = notifications;
    }
    @GetMapping("/orders") @PreAuthorize("hasRole('user')")
    public Map<String, Object> getOrders(@AuthenticationPrincipal Jwt jwt) {
        return Map.of("orders", List.of(Map.of("id", "demo-1", "item", "widget", "quantity", 1)),
                "caller", jwt.getClaimAsString("preferred_username"));
    }
    @PostMapping("/orders") @PreAuthorize("hasRole('manager')") @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> createOrder(@Valid @RequestBody OrderRequest order, @AuthenticationPrincipal Jwt jwt) {
        String id = UUID.randomUUID().toString();
        var reservation = inventory.reserve(jwt, id, order.item(), order.quantity());
        var notification = notifications.notifyOrder(id);
        return Map.of("id", id, "reserved", reservation, "notification", notification);
    }
}
