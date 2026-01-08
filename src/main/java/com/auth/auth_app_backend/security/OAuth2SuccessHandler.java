package com.auth.auth_app_backend.security;

import com.auth.auth_app_backend.entities.*;
import com.auth.auth_app_backend.repositories.RefreshTokenRepository;
import com.auth.auth_app_backend.repositories.RoleRepository;
import com.auth.auth_app_backend.repositories.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${app.auth.frontend.success-redirect:http://localhost:5173/auth/success}")
    private String frontEndSuccessUrl;

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        logger.info("Successful Authentication");

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();

        User user = null;

        // 1. Fetch Default Role
        Role defaultRole = roleRepository.findByName(AppRole.ROLE_USER.name())
                .orElseGet(() -> {
                    Role newRole = new Role();
                    newRole.setName(AppRole.ROLE_USER.name());
                    return roleRepository.save(newRole);
                });

        // 2. Identify or Create User
        switch (registrationId) {
            case "google" -> {
                String email = oAuth2User.getAttribute("email");
                String name = oAuth2User.getAttribute("name");
                String picture = oAuth2User.getAttribute("picture");
                String googleId = oAuth2User.getAttribute("sub");

                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(picture)
                        .enable(true)
                        .provider(Provider.GOOGLE)
                        .providerId(googleId)
                        .roles(Set.of(defaultRole))
                        .build();

                user = userRepository.findByEmail(email).orElseGet(() -> userRepository.save(newUser));
            }
            case "github" -> {
                String email = oAuth2User.getAttribute("email");
                String name = oAuth2User.getAttribute("name");
                String avatar = oAuth2User.getAttribute("avatar_url");
                String id = String.valueOf(oAuth2User.getAttributes().get("id"));

                if (email == null) email = name + "@github.com";

                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(avatar)
                        .enable(true)
                        .provider(Provider.GITHUB)
                        .providerId(id)
                        .roles(Set.of(defaultRole))
                        .build();

                user = userRepository.findByEmail(email).orElseGet(() -> userRepository.save(newUser));
            }
            default -> throw new RuntimeException("Invalid registration id");
        }

        // 3. Handle Refresh Token - THE FIX IS HERE
        User finalUser = user;
        Instant expiresAt = Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds());

        // Find existing token by User ID
        Optional<RefreshToken> existingTokenOpt = refreshTokenRepository.findByUserId(finalUser.getId());

        RefreshToken tokenToSave;
        String jti;

        if (existingTokenOpt.isPresent()) {
            // REUSE EXISTING JTI (This fixes the "Not Recognized" error)
            tokenToSave = existingTokenOpt.get();
            jti = tokenToSave.getJti();

            tokenToSave.setExpiresAt(expiresAt);
            tokenToSave.setRevoked(false);
        } else {
            // CREATE NEW JTI
            jti = UUID.randomUUID().toString();
            tokenToSave = RefreshToken.builder()
                    .jti(jti)
                    .user(finalUser)
                    .revoked(false)
                    .createdAt(Instant.now())
                    .expiresAt(expiresAt)
                    .build();
        }

        refreshTokenRepository.save(tokenToSave);

        // 4. Generate Tokens (Using the JTI we decided on above)
        String accessToken = jwtService.generateAccessToken(user);
        String refreshTokenString = jwtService.generateRefreshToken(user, jti);

        // 5. Set Cookie & Redirect
        cookieService.attachRefreshCookie(response, refreshTokenString, (int) jwtService.getRefreshTtlSeconds());

        String targetUrl = UriComponentsBuilder.fromUriString(frontEndSuccessUrl)
                .queryParam("accessToken", accessToken)
                .build().toUriString();

        response.sendRedirect(targetUrl);
    }
}