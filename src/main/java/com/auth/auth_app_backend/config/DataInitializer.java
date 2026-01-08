package com.auth.auth_app_backend.config;

import com.auth.auth_app_backend.entities.AppRole;
import com.auth.auth_app_backend.entities.Role;
import com.auth.auth_app_backend.entities.User;
import com.auth.auth_app_backend.repositories.RoleRepository;
import com.auth.auth_app_backend.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        // ensures that ROLE_USER and ROLE_ADMIN always exist in the DB
        for (AppRole appRole : AppRole.values()) {
            roleRepository.findByName(appRole.name()).orElseGet(() -> {
                Role newRole = new Role();
                newRole.setName(appRole.name());
                return roleRepository.save(newRole);
            });
        }

        // CREATE ADMIN USER
        if (userRepository.findByEmail("vanshbatham.pro@gmail.com").isEmpty()) {

            // Fetch the ADMIN role using the Enum (Safe!)
            Role adminRole = roleRepository.findByName(AppRole.ROLE_ADMIN.name())
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));

            User admin = new User();
            admin.setEmail("vanshbatham.pro@gmail.com");
            admin.setPassword(passwordEncoder.encode("admin@authx"));
            admin.setName("Vansh Batham");
            admin.setRoles(Set.of(adminRole));
            admin.setEnable(true);

            userRepository.save(admin);
            System.out.println("Admin user created successfully.");
        }
    }
}