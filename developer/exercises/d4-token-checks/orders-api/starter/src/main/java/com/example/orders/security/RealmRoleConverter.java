package com.example.orders.security;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/** Maps only realm roles from a signature-verified access token to Spring roles. */
public final class RealmRoleConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    @Override public AbstractAuthenticationToken convert(Jwt jwt) {
        Object realmAccess = jwt.getClaims().get("realm_access");
        Object rolesValue = realmAccess instanceof Map<?, ?> map ? map.get("roles") : null;
        Collection<?> roles = rolesValue instanceof Collection<?> values ? values : List.of();
        List<GrantedAuthority> authorities = roles.stream()
                .filter(String.class::isInstance).map(String.class::cast)
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role)).map(GrantedAuthority.class::cast).toList();
        return new JwtAuthenticationToken(jwt, authorities, jwt.getClaimAsString("preferred_username"));
    }
}
