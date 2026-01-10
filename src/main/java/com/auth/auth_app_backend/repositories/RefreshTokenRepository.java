package com.auth.auth_app_backend.repositories;

import com.auth.auth_app_backend.entities.RefreshToken;
import com.auth.auth_app_backend.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByJti(String jti);

    Optional<RefreshToken> findByUser(User user);

    Optional<RefreshToken> findByUserId(Long userId);

    void deleteByUser(User user);
}