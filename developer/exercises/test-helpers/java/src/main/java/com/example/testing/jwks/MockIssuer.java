package com.example.testing.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Signs test JWTs with local keys and serves them from a mock Keycloak JWKS.
 *
 * <p>Keys are generated in memory; nothing is written to disk. The JWKS is served at
 * {@code {issuer}/protocol/openid-connect/certs}, the path orders-api derives from
 * {@code ISSUER}. It publishes the RS256 key and an ES256 key, as a Keycloak realm with
 * both providers would, so an ES256 token carries a valid signature and only an
 * algorithm allowlist rejects it.
 *
 * <pre>{@code
 * try (MockIssuer issuer = MockIssuer.start()) {
 *     String good = issuer.token("orders-api");
 *     String bad = issuer.forge(Forgery.WRONG_AUD, "orders-api");
 * }
 * }</pre>
 */
public final class MockIssuer implements AutoCloseable {
    /** One property that makes an otherwise valid token invalid. */
    public enum Forgery {
        /** {@code aud} names another API. */
        WRONG_AUD,
        /** {@code iss} names another realm. */
        WRONG_ISS,
        /** {@code exp} passed ten minutes ago, beyond any 30 s skew. */
        EXPIRED,
        /** The header {@code kid} is not in the JWKS. */
        UNKNOWN_KID,
        /** HMAC-signed with a random secret under the RSA {@code kid}. */
        HS256,
        /** Signed by the published EC key: only an RS256 allowlist rejects it. */
        ES256,
        /** Signed by another RSA key under the published {@code kid}. */
        BAD_SIGNATURE
    }

    public static final String KID = "mock-rs256";
    public static final String EC_KID = "mock-es256";

    private final String realm;
    private final RSAKey rsa;
    private final RSAKey otherRsa;
    private final ECKey ec;
    private final HttpServer server;

    private MockIssuer(String realm) throws IOException, JOSEException {
        this.realm = realm;
        this.rsa = new RSAKeyGenerator(2048).keyID(KID).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).generate();
        this.otherRsa = new RSAKeyGenerator(2048).keyID(KID).generate();
        this.ec = new ECKeyGenerator(Curve.P_256).keyID(EC_KID).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256).generate();
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String prefix = "/realms/" + realm;
        server.createContext(prefix + "/protocol/openid-connect/certs", exchange -> respond(exchange, jwks().toString()));
        server.createContext(prefix + "/.well-known/openid-configuration", exchange -> respond(exchange,
                "{\"issuer\":\"" + issuer() + "\",\"jwks_uri\":\"" + jwksUri() + "\"}"));
        server.start();
    }

    /** Starts an issuer for realm {@code workshop} on an ephemeral loopback port. */
    public static MockIssuer start() {
        return start("workshop");
    }

    public static MockIssuer start(String realm) {
        try {
            return new MockIssuer(realm);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override public void close() {
        server.stop(0);
    }

    public String issuer() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/realms/" + realm;
    }

    public String jwksUri() {
        return issuer() + "/protocol/openid-connect/certs";
    }

    /** The public JWKS the endpoint serves. */
    public JWKSet jwks() {
        return new JWKSet(List.of(rsa.toPublicJWK(), ec.toPublicJWK()));
    }

    /** Keycloak-shaped access token claims; an override whose value is {@code null} removes the claim. */
    public JWTClaimsSet claims(String audience, Map<String, Object> overrides) {
        Instant now = Instant.now();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer());
        claims.put("aud", audience);
        claims.put("sub", "test-user");
        claims.put("azp", "test-client");
        claims.put("typ", "Bearer");
        claims.put("iat", Date.from(now));
        claims.put("nbf", Date.from(now));
        claims.put("exp", Date.from(now.plusSeconds(300)));
        claims.put("realm_access", Map.of("roles", List.of()));
        claims.put("resource_access", Map.of());
        claims.putAll(overrides);
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        claims.forEach((name, value) -> {
            if (value != null) builder.claim(name, value);
        });
        return builder.build();
    }

    /** Signs {@code claims} as-is with RS256, ES256, or HS256; a null {@code kid} uses the key's own. */
    public String sign(JWTClaimsSet claims, JWSAlgorithm alg, String kid) {
        try {
            JWSSigner signer;
            String defaultKid;
            if (JWSAlgorithm.RS256.equals(alg)) {
                signer = new RSASSASigner(rsa);
                defaultKid = KID;
            } else if (JWSAlgorithm.ES256.equals(alg)) {
                signer = new ECDSASigner(ec);
                defaultKid = EC_KID;
            } else if (JWSAlgorithm.HS256.equals(alg)) {
                byte[] secret = new byte[32];
                new SecureRandom().nextBytes(secret);
                signer = new MACSigner(secret);
                defaultKid = KID;
            } else {
                throw new IllegalArgumentException("unsupported alg " + alg);
            }
            return signWith(signer, alg, kid == null ? defaultKid : kid, claims);
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A valid RS256 access token for {@code audience}. */
    public String token(String audience) {
        return token(audience, Map.of());
    }

    public String token(String audience, Map<String, Object> overrides) {
        return sign(claims(audience, overrides), JWSAlgorithm.RS256, null);
    }

    /** A token that is valid except for the one property {@code kind} names. */
    public String forge(Forgery kind, String audience) {
        return forge(kind, audience, Map.of());
    }

    public String forge(Forgery kind, String audience, Map<String, Object> overrides) {
        Instant now = Instant.now();
        return switch (kind) {
            case WRONG_AUD -> token("another-api", overrides);
            case WRONG_ISS -> token(audience, merge(Map.of("iss", issuer() + "-other"), overrides));
            case EXPIRED -> token(audience, merge(Map.of(
                    "iat", Date.from(now.minusSeconds(900)),
                    "nbf", Date.from(now.minusSeconds(900)),
                    "exp", Date.from(now.minusSeconds(600))), overrides));
            case UNKNOWN_KID -> sign(claims(audience, overrides), JWSAlgorithm.RS256, "unknown-kid");
            case HS256 -> sign(claims(audience, overrides), JWSAlgorithm.HS256, null);
            case ES256 -> sign(claims(audience, overrides), JWSAlgorithm.ES256, null);
            case BAD_SIGNATURE -> {
                try {
                    yield signWith(new RSASSASigner(otherRsa), JWSAlgorithm.RS256, KID, claims(audience, overrides));
                } catch (JOSEException e) {
                    throw new IllegalStateException(e);
                }
            }
        };
    }

    private static String signWith(JWSSigner signer, JWSAlgorithm alg, String kid, JWTClaimsSet claims) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(alg).keyID(kid).type(JOSEObjectType.JWT).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        return jwt.serialize();
    }

    private static Map<String, Object> merge(Map<String, Object> base, Map<String, Object> overrides) {
        Map<String, Object> merged = new LinkedHashMap<>(base);
        merged.putAll(overrides);
        return merged;
    }

    private static void respond(HttpExchange exchange, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
