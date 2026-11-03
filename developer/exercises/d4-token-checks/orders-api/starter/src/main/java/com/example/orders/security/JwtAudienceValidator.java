package com.example.orders.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/** Audience restriction: a token minted for another API is not accepted here. */
public final class JwtAudienceValidator implements OAuth2TokenValidator<Jwt> {
    @Override public OAuth2TokenValidatorResult validate(Jwt jwt) {
        // ANTI-PATTERN: accepts a token minted for any API. Exercise D4: succeed only when
        // aud contains "orders-api", and otherwise fail with the OAuth2Error "bad_audience".
        return OAuth2TokenValidatorResult.success();
    }
}
