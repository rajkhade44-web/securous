package com.securous.backend.controllers;

import com.securous.backend.dto.SessionDto;
import com.securous.backend.dto.UserDto;
import com.securous.backend.entity.User;
import com.securous.backend.exception.ResourceNotFoundException;
import com.securous.backend.service.AuthService;
import com.securous.backend.service.SessionService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final SessionService sessionService;
    private final AuthService    authService;
    private final ModelMapper    modelMapper;

    // Current user profile
    @GetMapping("/me")
    public ResponseEntity<UserDto> getMe(
            @AuthenticationPrincipal User user) {
        return ResponseEntity.ok(modelMapper.map(user, UserDto.class));
    }

    // List all active sessions — pass current jti via header
    @GetMapping("/me/sessions")
    public ResponseEntity<List<SessionDto>> getSessions(
            @AuthenticationPrincipal User user,
            @RequestHeader(value = "X-Current-Jti",
                    required = false) String currentJti) {
        return ResponseEntity.ok(
                sessionService.getActiveSessions(user.getId(), currentJti));
    }

    // Revoke one specific session by jti
    @DeleteMapping("/me/sessions/{jti}")
    public ResponseEntity<Void> revokeSession(
            @PathVariable String jti,
            @AuthenticationPrincipal User user) throws ResourceNotFoundException {
        authService.revokeSession(jti, user.getId());
        return ResponseEntity.noContent().build();
    }

    // Revoke all sessions — logout all devices
    @DeleteMapping("/me/sessions")
    public ResponseEntity<Void> revokeAllSessions(
            @AuthenticationPrincipal User user) {
        authService.revokeAllSessions(user.getId());
        return ResponseEntity.noContent().build();
    }
}