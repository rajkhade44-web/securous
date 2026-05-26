package com.securous.backend.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "refresh_tokens",indexes = {
        @Index(name = "idx_refresh_token_jti",columnList = "jti"),
        @Index(name = "idx_refresh_token_user_id",columnList = "userId")
})
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "jti", nullable = false, updatable = false, unique = true)
    private String jti;

    @ManyToOne(fetch = FetchType.LAZY,optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @Column(nullable = false, updatable = false)
    private Instant created;

    @Column(nullable = false)
    private Instant expiredAt;

    @Column(nullable = false)
    private boolean revoked = false;

    @Column(name = "replaced_by_jti")
    private String replacedByJti;

    @Column(name = "device_info")
    private String deviceInfo;

    @Column(name = "ip_address")
    private String ipAddress;
}
