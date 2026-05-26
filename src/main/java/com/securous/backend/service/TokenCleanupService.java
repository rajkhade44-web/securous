package com.securous.backend.service;

import com.securous.backend.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenCleanupService {

    private final RefreshTokenRepository refreshTokenRepository;

    // Runs every day at midnight
    @Transactional
    @Scheduled(cron = "0 0 0 * * *")
    public void deleteExpiredTokens() {
        refreshTokenRepository.deleteAllExpiredBefore(Instant.now());
        log.info("Expired refresh tokens cleaned up");
    }
}