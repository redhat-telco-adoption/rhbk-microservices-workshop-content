package com.example.orders.logging;

import io.opentelemetry.api.trace.Span;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/** Runs inside the server span and emits one completion record, including security failures. */
@Component
public class RequestCompletionFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(RequestCompletionFilter.class);
    public static final String REASON = RequestCompletionFilter.class.getName() + ".reason";

    @Override protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        try { chain.doFilter(req, res); }
        finally {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            JwtAuthenticationToken token = auth instanceof JwtAuthenticationToken jwtAuth && auth.isAuthenticated() ? jwtAuth : null;
            int status = res.getStatus();
            String reason = (String) req.getAttribute(REASON);
            String decision = status >= 400 ? "deny" : "allow";
            if (status == 401 && reason == null) reason = req.getHeader("Authorization") == null ? "missing_token" : "invalid_token";
            if (status == 403 && reason == null) reason = "missing_role";
            var span = Span.current();
            var event = log.atLevel(status >= 400 ? org.slf4j.event.Level.WARN : org.slf4j.event.Level.INFO);
            event.addKeyValue("timestamp", Instant.now().toString()).addKeyValue("level", status >= 400 ? "WARN" : "INFO")
                .addKeyValue("service", "orders-api").addKeyValue("trace_id", span.getSpanContext().isValid() ? span.getSpanContext().getTraceId() : null)
                .addKeyValue("span_id", span.getSpanContext().isValid() ? span.getSpanContext().getSpanId() : null)
                .addKeyValue("event", "request_completed").addKeyValue("subject", token == null ? null : token.getToken().getSubject())
                .addKeyValue("username", token == null ? null : token.getToken().getClaimAsString("preferred_username"))
                .addKeyValue("client_id", token == null ? null : token.getToken().getClaimAsString("azp"))
                .addKeyValue("roles", token == null ? List.of() : token.getAuthorities().stream().map(a -> a.getAuthority().replaceFirst("^ROLE_", "")).sorted().toList())
                .addKeyValue("decision", decision).addKeyValue("reason", reason)
                .addKeyValue("path", req.getRequestURI()).addKeyValue("status", status).log("request completed");
        }
    }
    public static String reason(Exception ex) {
        String message = ex.getMessage() == null ? "" : ex.getMessage().toLowerCase();
        if (message.contains("bad_audience") || message.contains("audience")) return "bad_audience";
        if (message.contains("issuer")) return "bad_issuer";
        if (message.contains("expired") || message.contains("timestamp")) return "expired";
        if (message.contains("typ")) return "invalid_token";
        if (ex instanceof OAuth2AuthenticationException) return "invalid_token";
        return "invalid_token";
    }
}
