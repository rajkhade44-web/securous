package com.securous.backend.dto;

import java.time.Instant;

public record SessionDto(
        String jti,
        String deviceInfo,
        String ipAddress,
        Instant createdAt,
        Instant expiresAt,
        boolean current
) {
}
