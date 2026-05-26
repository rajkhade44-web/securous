package com.securous.backend.service;

import com.securous.backend.dto.*;
import com.securous.backend.entity.RefreshToken;
import com.securous.backend.entity.Role;
import com.securous.backend.entity.User;
import com.securous.backend.exception.ResourceNotFoundException;
import com.securous.backend.repository.RefreshTokenRepository;
import com.securous.backend.repository.RoleRepository;
import com.securous.backend.repository.UserRepository;
import com.securous.backend.security.CookieService;
import com.securous.backend.security.jwt.JwtProperties;
import com.securous.backend.security.jwt.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapper modelMapper;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;
    private final TokenBlackListService blackListService;

    // 1. Register
    @Transactional
    public UserDto register(RegisterRequest registerRequest) {
        if(userRepository.findByEmail(registerRequest.getEmail()).isPresent()){
            throw new BadCredentialsException("An account with this email already exists");
        }

        Role role = roleRepository.findByName("ROLE_USER").orElseThrow(()->new RuntimeException("ROLE_USER not found - seed your role table"));

        User user = User.builder()
                .name(registerRequest.getName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .enabled(true)
                .roles(Set.of(role))
                .build();

        userRepository.save(user);

        log.info("Registered new User {}",user.getEmail());

        return modelMapper.map(user, UserDto.class);
    }

    //2. Login
    @Transactional
    public TokenResponse login(LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest httpRequest){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.email(),loginRequest.password())
        );

        User user = userRepository.findByEmail(loginRequest.email()).orElseThrow(()->new BadCredentialsException("User with email "+loginRequest.email()+" is not available."));

        if(!user.isEnabled()){
            throw new DisabledException("Account is disabled");
        }

        long activeCount = refreshTokenRepository.countByUserIdAndRevokedFalse(user.getId());
        if(activeCount>= jwtProperties.maxSessions()){
            refreshTokenRepository
                    .findFirstByUserIdAndRevokedFalseOrderByCreatedAsc(
                            user.getId())
                    .ifPresent(oldest -> {
                        // Revoke it in DB
                        oldest.setRevoked(true);
                        refreshTokenRepository.save(oldest);

                        // Immediately blacklist its access token in Redis
                        blackListService.blacklist(
                                oldest.getJti(),
                                Date.from(Instant.now().plusSeconds(
                                        jwtProperties.accessTokenLifeCycleSeconds())));

                        log.info("Max sessions reached — evicted oldest " +
                                        "session jti: {} for userId: {}",
                                oldest.getJti(), user.getId());
                    });

        }

        String accessToken = jwtService.generateAccessToken(user);
        long expiresIn = jwtService.getExpiryInSeconds(accessToken);

        String jti = UUID.randomUUID().toString();

        String deviceInfo = parseDeviceInfo(
                httpRequest.getHeader("User-Agent"));
        String ipAddress  = extractIpAddress(httpRequest);

        refreshTokenRepository.save(RefreshToken.builder()
                        .user(user)
                        .jti(jti)
                        .created(Instant.now())
                        .expiredAt(Instant.now().plusSeconds(jwtProperties.refreshTokenTtlSeconds()))
                        .revoked(false)
                        .deviceInfo(deviceInfo)
                        .ipAddress(ipAddress)
                        .build());

        String refreshToken = jwtService.generateRefreshToken(user,jti);

        cookieService.attachRefreshCookie(response,refreshToken,expiresIn);
        cookieService.addNoStoreHeaders(response);

        log.info("Login — userId: {} device: {} activeSessions: {}",
                user.getId(), deviceInfo, activeCount + 1);

        return TokenResponse.of(accessToken,expiresIn,modelMapper.map(user, UserDto.class));
    }

    @Transactional
    public TokenResponse refresh(RefreshTokenRequest body,
                                 HttpServletRequest request,
                                 HttpServletResponse response) {

        String token = readRefreshTokenFromRequest(body, request)
                .orElseThrow(() -> new BadCredentialsException("Refresh token is missing"));

        if (!jwtService.isRefreshToken(token)) {
            throw new BadCredentialsException("Invalid token type");
        }

        String jti = jwtService.getJtiFromToken(token);
        UUID userId = UUID.fromString(jwtService.getUserIdFromToken(token).toString());

        RefreshToken stored = refreshTokenRepository.findByJti(jti)
                .orElseThrow(() -> new BadCredentialsException("Refresh token not recognised"));

        validateRefreshToken(stored, jti, userId);

        // Rotate tokens
        String newJti = UUID.randomUUID().toString();
        rotateRefreshToken(stored, newJti);

        // Create new session
        User user = stored.getUser();
        refreshTokenRepository.save(buildNewRefreshToken(stored, newJti));

        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user, newJti);

        cookieService.attachRefreshCookie(response, newRefreshToken, jwtProperties.refreshTokenTtlSeconds());
        cookieService.addNoStoreHeaders(response);

        log.info("Token rotated — userId: {} oldJti: {} newJti: {}",
                user.getId(), jti, newJti);

        return TokenResponse.of(
                newAccessToken,
                jwtService.getExpiresInSeconds(newAccessToken),
                modelMapper.map(user, UserDto.class)
        );
    }

    private void validateRefreshToken(RefreshToken stored, String jti, UUID userId) {

        if (stored.isRevoked()) {
            log.warn("REVOKED token used — jti: {}", jti);
            throw new BadCredentialsException("Refresh token has been revoked");
        }

        if (stored.getExpiredAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh token has expired");
        }

        if (!stored.getUser().getId().equals(userId)) {
            log.warn("USER MISMATCH — token: {} stored: {}", userId, stored.getUser().getId());
            throw new BadCredentialsException("Token subject mismatch");
        }
    }

    private void rotateRefreshToken(RefreshToken stored, String newJti) {
        stored.setRevoked(true);
        stored.setReplacedByJti(newJti);

        refreshTokenRepository.save(stored);

        blackListService.blacklist(
                stored.getJti(),
                Date.from(Instant.now().plusSeconds(jwtProperties.accessTokenLifeCycleSeconds()))
        );
    }

    private RefreshToken buildNewRefreshToken(RefreshToken old, String newJti) {
        Instant now = Instant.now();

        return RefreshToken.builder()
                .jti(newJti)
                .user(old.getUser())
                .created(now)
                .expiredAt(now.plusSeconds(jwtProperties.refreshTokenTtlSeconds()))
                .revoked(false)
                .deviceInfo(old.getDeviceInfo())
                .ipAddress(old.getIpAddress())
                .build();
    }

    @Transactional
    public void logout(RefreshTokenRequest body,
                       HttpServletRequest request,
                       HttpServletResponse response) {

        Optional<String> tokenOpt = readRefreshTokenFromRequest(body, request);

        tokenOpt.ifPresent(token -> {
            if (jwtService.isRefreshToken(token)) {

                String jti = jwtService.getJtiFromToken(token);

                refreshTokenRepository.findByJti(jti).ifPresent(stored -> {
                    stored.setRevoked(true);
                    refreshTokenRepository.save(stored);

                    blackListService.blacklist(
                            jti,
                            Date.from(Instant.now()
                                    .plusSeconds(jwtProperties.accessTokenLifeCycleSeconds()))
                    );

                    log.info("Logout — revoked jti: {}", jti);
                });
            }
        });

        // always executed cleanup
        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeaders(response);
        SecurityContextHolder.clearContext();
    }

    @Transactional
    public void revokeSession(String jti, UUID currentUserId) throws ResourceNotFoundException {

        RefreshToken token = refreshTokenRepository.findByJti(jti)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found"));

        if (!token.getUser().getId().equals(currentUserId)) {
            throw new AccessDeniedException("Not your session");
        }

        token.setRevoked(true);
        refreshTokenRepository.save(token);

        blackListService.blacklist(
                token.getJti(),
                Date.from(Instant.now().plusSeconds(jwtProperties.accessTokenLifeCycleSeconds()))
        );

        log.info("Session revoked — jti: {} by userId: {}", jti, currentUserId);
    }

    @Transactional
    public void revokeAllSessions(UUID userId) {

        // 1. Get all active refresh tokens of user
        List<RefreshToken> tokens =
                refreshTokenRepository
                        .findAllByUserIdAndRevokedFalse(userId);

        // 2. Revoke each token + blacklist access tokens
        for (RefreshToken token : tokens) {

            token.setRevoked(true);

            blackListService.blacklist(
                    token.getJti(),
                    Date.from(Instant.now().plusSeconds(
                            jwtProperties.accessTokenLifeCycleSeconds()))
            );
        }

        // 3. Save all revoked tokens in DB
        refreshTokenRepository.saveAll(tokens);

        // 4. (Optional cleanup if your repo supports it)
        refreshTokenRepository.revokeAllByUserId(userId);

        log.info("All sessions revoked for userId: {}", userId);
    }

    private Optional<String> readRefreshTokenFromRequest(
            RefreshTokenRequest body,
            HttpServletRequest request) {

        // 1. COOKIE (BEST + MOST SECURE)
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {

                if (cookieService
                        .getRefreshTokenCookieName()
                        .equals(cookie.getName())
                        && cookie.getValue() != null
                        && !cookie.getValue().isBlank()) {

                    return Optional.of(cookie.getValue());
                }
            }
        }

        // 2. REQUEST BODY
        if (body != null
                && body.refreshToken() != null
                && !body.refreshToken().isBlank()) {

            return Optional.of(body.refreshToken());
        }

        // 3. CUSTOM HEADER
        String headerToken = request.getHeader("X-Refresh-Token");

        if (headerToken != null && !headerToken.isBlank()) {
            return Optional.of(headerToken);
        }

        // 4. AUTHORIZATION HEADER (LAST OPTION)
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {

            String token = authHeader.substring(7).trim();

            if (!token.isBlank() && jwtService.isRefreshToken(token)) {
                return Optional.of(token);
            }
        }

        // NOTHING FOUND
        return Optional.empty();
    }

    private String parseDeviceInfo(String userAgent) {
        if (userAgent == null) return "Unknown";
        if (userAgent.contains("iPhone") || userAgent.contains("iPad"))
            return "iOS Device";
        if (userAgent.contains("Android"))  return "Android Device";
        if (userAgent.contains("Windows"))  return "Windows Browser";
        if (userAgent.contains("Mac"))      return "Mac Browser";
        if (userAgent.contains("Linux"))    return "Linux Browser";
        return "Unknown Device";
    }

    private String extractIpAddress(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip != null && !ip.isBlank()) {
            return ip.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
