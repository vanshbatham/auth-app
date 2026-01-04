package com.auth.auth_app_backend.controllers;

import com.auth.auth_app_backend.dtos.LoginRequest;
import com.auth.auth_app_backend.dtos.TokenResponse;
import com.auth.auth_app_backend.dtos.UserDTO;
import com.auth.auth_app_backend.entities.User;
import com.auth.auth_app_backend.repositories.UserRepository;
import com.auth.auth_app_backend.security.JwtService;
import com.auth.auth_app_backend.services.impl.AuthServiceImpl;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthServiceImpl authService;

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final ModelMapper modelMapper;

    @PostMapping("/register")
    public ResponseEntity<UserDTO> registerUser(@RequestBody UserDTO userDTO) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDTO));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest) {
        //authenticate
        Authentication authentication = authenticate(loginRequest);
        User user = userRepository.findByEmail(loginRequest.email())
                .orElseThrow(() -> new BadCredentialsException("Invalid Username or Password!"));
        if (!user.isEnable()) {
            throw new DisabledException("User is disabled.");
        }

        //generate token
        String accessToken = jwtService.generateAccessToken(user);
        TokenResponse tokenResponse = TokenResponse.of(accessToken, "",
                jwtService.getAccessTtlSeconds(), modelMapper.map(user, UserDTO.class));
        return new ResponseEntity<>(tokenResponse, HttpStatus.OK);
    }

    private Authentication authenticate(LoginRequest loginRequest) {
        try {
            return authenticationManager.authenticate(new
                    UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));
        } catch (Exception e) {
            throw new BadCredentialsException("Invalid Username or Password!");
        }
    }
}
