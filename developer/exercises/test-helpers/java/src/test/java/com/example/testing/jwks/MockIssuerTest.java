package com.example.testing.jwks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.testing.jwks.MockIssuer.Forgery;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/** Verifies the helper's tokens with the decoder and validators apps/orders-api configures. */
class MockIssuerTest {
    private static final String AUDIENCE = "orders-api";
    private static MockIssuer issuer;

    @BeforeAll static void start() {
        issuer = MockIssuer.start();
    }

    @AfterAll static void stop() {
        issuer.close();
    }

    /** The orders-api checks, each of which a test can relax. */
    private static NimbusJwtDecoder decoder(String audience, String iss, Duration skew, SignatureAlgorithm... algorithms) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(issuer.jwksUri())
                .jwsAlgorithms(set -> set.addAll(List.of(algorithms))).build();
        OAuth2TokenValidator<Jwt> typ = new JwtClaimValidator<String>("typ", "Bearer"::equals);
        OAuth2TokenValidator<Jwt> subject = new JwtClaimValidator<String>("sub", v -> v != null && !v.isBlank());
        OAuth2TokenValidator<Jwt> aud = jwt -> jwt.getAudience().contains(audience)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("bad_audience"));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(skew), new JwtIssuerValidator(iss), typ, subject, aud));
        return decoder;
    }

    private static NimbusJwtDecoder ordersApi() {
        return decoder(AUDIENCE, issuer.issuer(), Duration.ofSeconds(30), SignatureAlgorithm.RS256);
    }

    @Test void servesTheJwksAtTheKeycloakPathWithPublicKeysOnly() throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(issuer.jwksUri())).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains(MockIssuer.KID, MockIssuer.EC_KID).doesNotContain("\"d\"");
        assertThat(issuer.issuer()).endsWith("/realms/workshop");
    }

    @Test void aValidTokenPassesTheOrdersApiChecks() {
        Jwt jwt = ordersApi().decode(issuer.token(AUDIENCE, Map.of("sub", "alice")));
        assertThat(jwt.getSubject()).isEqualTo("alice");
        assertThat(jwt.getAudience()).containsExactly(AUDIENCE);
        assertThat(jwt.getClaimAsString("typ")).isEqualTo("Bearer");
    }

    @Test void eachForgeryIsRejectedWithItsReason() {
        Map<Forgery, String> expected = new EnumMap<>(Forgery.class);
        expected.put(Forgery.WRONG_AUD, "bad_audience");
        expected.put(Forgery.WRONG_ISS, "iss");
        expected.put(Forgery.EXPIRED, "expired");
        expected.put(Forgery.UNKNOWN_KID, "no matching key");
        expected.put(Forgery.HS256, "no matching key");
        expected.put(Forgery.ES256, "no matching key");
        expected.put(Forgery.BAD_SIGNATURE, "Invalid signature");
        assertThat(expected.keySet()).containsExactlyInAnyOrder(Forgery.values());
        expected.forEach((kind, reason) -> assertThatThrownBy(() -> ordersApi().decode(issuer.forge(kind, AUDIENCE)))
                .as(kind.name())
                .isInstanceOf(BadJwtException.class)
                .satisfies(e -> assertThat(reason(e)).as(kind.name()).contains(reason)));
    }

    /** The message plus, for a validator failure, every error code and description. */
    private static String reason(Throwable e) {
        StringBuilder text = new StringBuilder(String.valueOf(e.getMessage()));
        if (e instanceof JwtValidationException invalid) {
            invalid.getErrors().forEach(error -> text.append(' ').append(error.getErrorCode())
                    .append(' ').append(error.getDescription()));
        }
        return text.toString();
    }

    @Test void claimFailuresAreValidationErrors() {
        for (Forgery kind : List.of(Forgery.WRONG_AUD, Forgery.WRONG_ISS, Forgery.EXPIRED)) {
            assertThatThrownBy(() -> ordersApi().decode(issuer.forge(kind, AUDIENCE)))
                    .as(kind.name()).isInstanceOf(JwtValidationException.class);
        }
    }

    @Test void eachForgeryDiffersOnlyInItsOneProperty() {
        // Relaxing exactly the check under test lets the token through, so an exercise
        // test fails when that check is missing from the starter.
        Duration skew = Duration.ofSeconds(30);
        decoder("another-api", issuer.issuer(), skew, SignatureAlgorithm.RS256)
                .decode(issuer.forge(Forgery.WRONG_AUD, AUDIENCE));
        decoder(AUDIENCE, issuer.issuer() + "-other", skew, SignatureAlgorithm.RS256)
                .decode(issuer.forge(Forgery.WRONG_ISS, AUDIENCE));
        decoder(AUDIENCE, issuer.issuer(), Duration.ofHours(1), SignatureAlgorithm.RS256)
                .decode(issuer.forge(Forgery.EXPIRED, AUDIENCE));
        decoder(AUDIENCE, issuer.issuer(), skew, SignatureAlgorithm.RS256, SignatureAlgorithm.ES256)
                .decode(issuer.forge(Forgery.ES256, AUDIENCE));
    }

    @Test void overridesAddAndRemoveClaims() throws Exception {
        Map<String, Object> overrides = new HashMap<>();
        overrides.put("realm_access", Map.of("roles", List.of("orders-writer")));
        overrides.put("azp", null);
        var claims = SignedJWT.parse(issuer.token(AUDIENCE, overrides)).getJWTClaimsSet();
        assertThat(claims.getJSONObjectClaim("realm_access")).containsEntry("roles", List.of("orders-writer"));
        assertThat(claims.getClaims()).doesNotContainKey("azp");
    }
}
