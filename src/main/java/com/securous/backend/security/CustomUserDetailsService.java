package com.securous.backend.security;

import com.securous.backend.entity.User;
import com.securous.backend.exception.ResourceNotFoundException;
import com.securous.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = null;
        try {
            UUID userId = UUID.fromString(username);
            user = userRepository.findById(userId).orElseThrow(()->new UsernameNotFoundException("User with id"+username+" not found"));
            return new CustomUserDetails(user);
        } catch (IllegalArgumentException e) {
            user = userRepository.findByEmail(username).orElseThrow(()->new UsernameNotFoundException("User with email"+username+" not found"));
            return new CustomUserDetails(user);
        }
    }
}
