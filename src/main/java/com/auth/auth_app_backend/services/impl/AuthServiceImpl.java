package com.auth.auth_app_backend.services.impl;

import com.auth.auth_app_backend.dtos.UserDTO;
import com.auth.auth_app_backend.services.AuthService;
import com.auth.auth_app_backend.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;

    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDTO registerUser(UserDTO userDTO) {
        //logic
        //verifying email
        //verifying password
        //default roles
        userDTO.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        return userService.createUser(userDTO);
    }
}
