package com.securous.backend.security.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(
        String secret,
        String issuer,
        long accessTokenLifeCycleSeconds,
        long refreshTokenTtlSeconds,
        String cookieName,
        boolean cookieSecure,
        boolean cookieHttpOnly,
        String cookieSameSite,
        String cookieDomain
) {
}

