package com.example.orders.api;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import com.example.orders.downstream.InventoryClient;
import com.example.orders.downstream.NotificationsClient;

class OrdersControllerValidationTest {
  private InventoryClient inventory;
  private NotificationsClient notifications;
  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    inventory = org.mockito.Mockito.mock(InventoryClient.class);
    notifications = org.mockito.Mockito.mock(NotificationsClient.class);
    when(inventory.reserve(any(Jwt.class), anyString(), anyString(), anyInt())).thenReturn(Map.of("ok", true));
    when(notifications.notifyOrder(anyString())).thenReturn(Map.of("ok", true));
    Jwt caller = Jwt.withTokenValue("test-token").header("alg", "RS256").claim("sub", "test-user").build();
    HandlerMethodArgumentResolver principalResolver = new HandlerMethodArgumentResolver() {
      @Override
      public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(AuthenticationPrincipal.class)
            && Jwt.class.isAssignableFrom(parameter.getParameterType());
      }

      @Override
      public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer container,
          NativeWebRequest request, WebDataBinderFactory binderFactory) {
        return caller;
      }
    };
    var validator = new LocalValidatorFactoryBean();
    validator.afterPropertiesSet();
    mvc = MockMvcBuilders.standaloneSetup(new OrdersController(inventory, notifications))
        .setValidator(validator)
        .setCustomArgumentResolvers(principalResolver)
        .build();
  }

  @Test
  void bothValidBoundariesReachTheDownstreamClients() throws Exception {
    postOrder("x", 1);
    postOrder("x".repeat(120), 1000);

    verify(inventory, org.mockito.Mockito.times(2)).reserve(any(Jwt.class), anyString(), anyString(), anyInt());
    verify(notifications, org.mockito.Mockito.times(2)).notifyOrder(anyString());
  }

  @Test
  void invalidLengthAndQuantityAreRejectedBeforeTokenExchangeOrDownstreamCalls() throws Exception {
    rejectOrder("x".repeat(121), 1);
    rejectOrder("valid-item", 0);
    rejectOrder("valid-item", 1001);
    rejectOrder("   ", 1);

    verifyNoInteractions(inventory, notifications);
  }

  private void postOrder(String item, int quantity) throws Exception {
    mvc.perform(post("/orders").contentType("application/json")
        .content("{\"item\":\"" + item + "\",\"quantity\":" + quantity + "}"))
        .andExpect(status().isCreated());
  }

  private void rejectOrder(String item, int quantity) throws Exception {
    String escapedItem = item.replace("\\", "\\\\").replace("\"", "\\\"");
    mvc.perform(post("/orders").contentType("application/json")
        .content("{\"item\":\"" + escapedItem + "\",\"quantity\":" + quantity + "}"))
        .andExpect(status().isBadRequest());
  }
}
