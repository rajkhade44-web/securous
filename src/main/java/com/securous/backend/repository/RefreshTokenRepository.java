package com.securous.backend.repository;

import com.securous.backend.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    List<RefreshToken> findAllByUserIdAndRevokedFalse(UUID userId);
    long countByUserIdAndRevokedFalse(UUID userId);
    Optional<RefreshToken> findFirstByUserIdAndRevokedFalseOrderByCreatedAsc(UUID userId);

    @Modifying
    @Query("UPDATE RefreshToken r SET r.revoked = true WHERE r.user.id = :userId")
    void revokeAllByUserId(UUID userId);

    @Modifying
    @Query("DELETE FROM RefreshToken r WHERE r.expiresAt < :now")
    void deleteAllExpiredBefore(Instant now);

    Optional<RefreshToken> findByJti(String jti);
}
