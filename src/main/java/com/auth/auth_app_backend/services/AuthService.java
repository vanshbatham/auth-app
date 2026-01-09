package com.auth.auth_app_backend.services;

import com.auth.auth_app_backend.dtos.UserDTO;

public interface AuthService {
    UserDTO registerUser(UserDTO userDTO);

    void forgotPassword(String email);

    void resetPassword(String token, String newPassword);
}
