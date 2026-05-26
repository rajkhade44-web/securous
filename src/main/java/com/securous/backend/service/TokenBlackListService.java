package com.securous.backend.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlackListService {
    private static final String PREFIX = "blacklist:";

    private final StringRedisTemplate redisTemplate;

    public void blacklist(String jti, Date expiresAt){
        long remaining = expiresAt.toInstant().getEpochSecond() - Instant.now().getEpochSecond();

        if(remaining<=0){
            log.debug("Token already expired -skip blacklist jti: {}", jti);
            return;
        }

        redisTemplate.opsForValue().set(
                PREFIX+jti,"revoked", Duration.ofSeconds(remaining)
        );

        log.info("Blacklisted jti: {} TTL: {}s", jti, remaining);
    }

    public boolean isBlacklisted(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(PREFIX+jti));
    }
}
