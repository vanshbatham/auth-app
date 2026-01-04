package com.auth.auth_app_backend.dtos;

public record TokenResponse(String accessToken,
                            String refreshToken,
                            Long expiresIn,
                            String tokenType,
                            UserDTO userDTO
) {

    public static TokenResponse of(String accessToken, String refreshToken, Long expiresIn, UserDTO userDTO) {
        return new TokenResponse(accessToken, refreshToken, expiresIn, "Bearer", userDTO);

    }
}
