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
import java.util.HashSet;
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

        // fetch default role
        Role defaultRole = roleRepository.findByName(AppRole.ROLE_USER.name())
                .orElseGet(() -> {
                    Role newRole = new Role();
                    newRole.setName(AppRole.ROLE_USER.name());
                    return roleRepository.save(newRole);
                });

        // identify or create user
        switch (registrationId) {
            case "google" -> {
                String email = oAuth2User.getAttribute("email");
                String name = oAuth2User.getAttribute("name");
                String picture = oAuth2User.getAttribute("picture");
                String googleId = oAuth2User.getAttribute("sub");

                // find existing or create new
                user = userRepository.findByEmail(email).orElseGet(() -> {
                    User newUser = User.builder()
                            .email(email)
                            .name(name)
                            .image(picture)
                            .enable(true)
                            .provider(Provider.GOOGLE)
                            .providerId(googleId)
                            .roles(new HashSet<>(Set.of(defaultRole))) // Ensure Mutable Set
                            .build();
                    return userRepository.save(newUser);
                });
            }
            case "github" -> {
                String email = oAuth2User.getAttribute("email");
                String name = oAuth2User.getAttribute("name");
                String avatar = oAuth2User.getAttribute("avatar_url");
                Object idObj = oAuth2User.getAttributes().get("id");
                String id = String.valueOf(idObj);

                if (email == null) email = name + "@github.com";
                String finalEmail = email;

                user = userRepository.findByEmail(email).orElseGet(() -> {
                    User newUser = User.builder()
                            .email(finalEmail)
                            .name(name)
                            .image(avatar)
                            .enable(true)
                            .provider(Provider.GITHUB)
                            .providerId(id)
                            .roles(new HashSet<>(Set.of(defaultRole)))
                            .build();
                    return userRepository.save(newUser);
                });
            }
            default -> throw new RuntimeException("Invalid registration id");
        }

        // handle Refresh Token
        User finalUser = user;
        Instant expiresAt = Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds());

        // find existing token by User ID
        Optional<RefreshToken> existingTokenOpt = refreshTokenRepository.findByUserId(finalUser.getId());

        RefreshToken tokenToSave;
        String jti;

        if (existingTokenOpt.isPresent()) {
            tokenToSave = existingTokenOpt.get();
            jti = tokenToSave.getJti();
            tokenToSave.setExpiresAt(expiresAt);
            tokenToSave.setRevoked(false);
        } else {
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

        // generate Tokens
        String accessToken = jwtService.generateAccessToken(user);
        String refreshTokenString = jwtService.generateRefreshToken(user, jti);

        // set cookie & redirect
        cookieService.attachRefreshCookie(response, refreshTokenString, (int) jwtService.getRefreshTtlSeconds());

        String targetUrl = UriComponentsBuilder.fromUriString(frontEndSuccessUrl)
                .queryParam("accessToken", accessToken)
                .queryParam("refreshToken", refreshTokenString)
                .build().toUriString();

        response.sendRedirect(targetUrl);
    }
}