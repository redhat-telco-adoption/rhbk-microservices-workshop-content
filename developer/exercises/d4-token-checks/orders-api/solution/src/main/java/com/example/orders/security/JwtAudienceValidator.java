package com.example.orders.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/** Audience restriction: a token minted for another API is not accepted here. */
public final class JwtAudienceValidator implements OAuth2TokenValidator<Jwt> {
    @Override public OAuth2TokenValidatorResult validate(Jwt jwt) {
        return jwt.getAudience().contains("orders-api")
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("bad_audience"));
    }
}
