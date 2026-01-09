package com.auth.auth_app_backend.services.impl;

import com.auth.auth_app_backend.dtos.UserDTO;
import com.auth.auth_app_backend.entities.PasswordResetToken;
import com.auth.auth_app_backend.entities.User;
import com.auth.auth_app_backend.repositories.PasswordResetTokenRepository;
import com.auth.auth_app_backend.repositories.UserRepository;
import com.auth.auth_app_backend.services.AuthService;
import com.auth.auth_app_backend.services.EmailService;
import com.auth.auth_app_backend.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailService emailService;

    @Value("${app.frontend.url:http://localhost:5173}")
    private String frontendUrl;

    @Override
    public UserDTO registerUser(UserDTO userDTO) {
        userDTO.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        return userService.createUser(userDTO);
    }

    @Override
    public void forgotPassword(String email) {
        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

            // Generate Token
            String token = UUID.randomUUID().toString();

            // Remove existing token if exists
            passwordResetTokenRepository.findByUser(user).ifPresent(passwordResetTokenRepository::delete);

            PasswordResetToken resetToken = PasswordResetToken.builder()
                    .token(token)
                    .user(user)
                    .expiryDate(Instant.now().plusSeconds(86400))
                    .build();

            passwordResetTokenRepository.save(resetToken);

            // Send Email
            String resetLink = frontendUrl + "/reset-password?token=" + token;
            String emailBody = "Click the link to reset your password: " + resetLink;

            System.out.println("Attempting to send email to: " + user.getEmail());
            emailService.sendEmail(user.getEmail(), "Password Reset Request", emailBody);
            System.out.println("Email sent successfully!");

        } catch (Exception e) {
            // THIS WILL SHOW YOU THE REAL ERROR IN THE CONSOLE
            e.printStackTrace();
            throw new RuntimeException("Failed to process forgot password request: " + e.getMessage());
        }
    }

    @Override
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid or expired token"));

        if (resetToken.getExpiryDate().isBefore(Instant.now())) {
            passwordResetTokenRepository.delete(resetToken);
            throw new RuntimeException("Token has expired");
        }

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        passwordResetTokenRepository.delete(resetToken);
    }
}