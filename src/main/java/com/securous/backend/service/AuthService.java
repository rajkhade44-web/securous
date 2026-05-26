package com.securous.backend.service;

import com.securous.backend.dto.LoginRequest;
import com.securous.backend.dto.RegisterRequest;
import com.securous.backend.dto.TokenResponse;
import com.securous.backend.dto.UserDto;
import com.securous.backend.entity.RefreshToken;
import com.securous.backend.entity.Role;
import com.securous.backend.entity.User;
import com.securous.backend.repository.RefreshTokenRepository;
import com.securous.backend.repository.RoleRepository;
import com.securous.backend.repository.UserRepository;
import com.securous.backend.security.CookieService;
import com.securous.backend.security.jwt.JwtProperties;
import com.securous.backend.security.jwt.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

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
    public TokenResponse login(LoginRequest loginRequest, HttpServletResponse response){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.email(),loginRequest.password())
        );

        User user = userRepository.findByEmail(loginRequest.email()).orElseThrow(()->new BadCredentialsException("User with email "+loginRequest.email()+" is not available."));

        if(!user.isEnabled()){
            throw new DisabledException("Account is disabled");
        }

        String accessToken = jwtService.generateAccessToken(user);
        long expiresIn = jwtService.getExpiryInSeconds(accessToken);

        String jti = UUID.randomUUID().toString();

        refreshTokenRepository.save(RefreshToken.builder()
                        .user(user)
                        .jti(jti)
                        .created(Instant.now())
                        .expiredAt(Instant.now().plusSeconds(jwtProperties.refreshTokenTtlSeconds()))
                        .revoked(false)
                        .build());

        String refreshToken = jwtService.generateRefreshToken(user,jti);

        cookieService.attachRefreshCookie(response,refreshToken,expiresIn);
        cookieService.addNoStoreHeaders(response);

        log.info("Login success - userId: {}",user.getId());

        return TokenResponse.of(accessToken,expiresIn,modelMapper.map(user, UserDto.class));
    }
}
