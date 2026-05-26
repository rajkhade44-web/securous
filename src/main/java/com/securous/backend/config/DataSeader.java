package com.securous.backend.config;

import com.securous.backend.entity.Role;
import com.securous.backend.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class DataSeader implements ApplicationRunner {
    private final RoleRepository roleRepository;
    @Override
    public void run(ApplicationArguments args) throws Exception {
        seedRole("ROLE_USER");
        seedRole("ROLE_ADMIN");
    }

    private void seedRole(String name) {
        if (roleRepository.findByName(name).isEmpty()) {
            roleRepository.save(Role.builder().name(name).build());
            log.info("Seeded role: {}", name);
        }
    }
}
