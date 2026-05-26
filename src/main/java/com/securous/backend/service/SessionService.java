package com.securous.backend.service;

import com.securous.backend.dto.SessionDto;
import com.securous.backend.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SessionService {
    private final RefreshTokenRepository refreshTokenRepository;

    public List<SessionDto> getActiveSessions(UUID userId, String currentJti){
        return refreshTokenRepository
                .findAllByUserIdAndRevokedFalse(userId)
                .stream()
                .map(token->new SessionDto(
                        token.getJti(),
                        token.getDeviceInfo(),
                        token.getIpAddress(),
                        token.getCreated(),
                        token.getExpiredAt(),
                        token.getJti().equals(currentJti)
                        ))
                .toList();
    }
}
