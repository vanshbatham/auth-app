package com.auth.auth_app_backend.security;

import com.auth.auth_app_backend.entities.Provider;
import com.auth.auth_app_backend.entities.RefreshToken;
import com.auth.auth_app_backend.entities.User;
import com.auth.auth_app_backend.repositories.RefreshTokenRepository;
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

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${app.auth.frontend.success-redirect}")
    private String frontEndSuccessUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        logger.info("Successful Authentication");
        logger.info(authentication.toString());


        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        //identify user:
        String registrationId = "unknown";
        if (authentication instanceof OAuth2AuthenticationToken token) {
            registrationId = token.getAuthorizedClientRegistrationId();
        }

        logger.info("registrationId: " + registrationId);
        logger.info("user: " + oAuth2User.getAttributes().toString());

        User user;

        switch (registrationId) {
            case "google" -> {
                Object googleIdObj = oAuth2User.getAttributes().get("sub");
                Object emailObj = oAuth2User.getAttributes().get("email");
                Object nameObj = oAuth2User.getAttributes().get("name");
                Object pictureObj = oAuth2User.getAttributes().get("picture");

                String googleId = googleIdObj == null ? "" : googleIdObj.toString();
                String email = emailObj == null ? "" : emailObj.toString();
                String name = nameObj == null ? "" : nameObj.toString();
                String picture = pictureObj == null ? "" : pictureObj.toString();

                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(picture)
                        .enable(true)
                        .provider(Provider.GOOGLE)
                        .providerId(googleId)
                        .build();

                user = userRepository.findByEmail(email)
                        .orElseGet(() -> userRepository.save(newUser));
            }
            case "github" -> {
                String name = oAuth2User.getAttributes().getOrDefault("name", "").toString();
                String image = oAuth2User.getAttributes().getOrDefault("avatar_url", "").toString();
                String githubId = oAuth2User.getAttributes().getOrDefault("id", "").toString();
                String email = (String) oAuth2User.getAttributes().get("email");
                if (email == null) {
                    email = name + "@github.com";
                }

                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(image)
                        .enable(true)
                        .provider(Provider.GITHUB)
                        .providerId(githubId)
                        .build();

                user = userRepository.findByEmail(email)
                        .orElseGet(() -> userRepository.save(newUser));
            }

            default -> {
                throw new RuntimeException("Invalid registration id");
            }
        }

        //username
        //email
        //new user creation
        //jwt token --- redirect

        //refresh

        //refresh token
        String jti = UUID.randomUUID().toString();
        RefreshToken refreshTokenOb = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .revoked(false)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .build();

        refreshTokenRepository.findByUser(user)
                .ifPresentOrElse(
                        existing -> {
                            existing.setJti(jti);
                            existing.setExpiresAt(refreshTokenOb.getExpiresAt());
                            existing.setRevoked(false);
                            refreshTokenRepository.save(existing);
                        },
                        () -> refreshTokenRepository.save(refreshTokenOb)
                );


        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenOb.getJti());
        cookieService.attachRefreshCookie(response, refreshToken, (int) jwtService.getRefreshTtlSeconds());
//        response.sendRedirect();

        response.sendRedirect(frontEndSuccessUrl);
    }
}
