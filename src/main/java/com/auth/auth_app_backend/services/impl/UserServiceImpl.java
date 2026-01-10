package com.auth.auth_app_backend.services.impl;

import com.auth.auth_app_backend.dtos.UserDTO;
import com.auth.auth_app_backend.entities.Provider;
import com.auth.auth_app_backend.entities.User;
import com.auth.auth_app_backend.exceptions.ResourceNotFoundException;
import com.auth.auth_app_backend.repositories.RefreshTokenRepository;
import com.auth.auth_app_backend.repositories.UserRepository;
import com.auth.auth_app_backend.services.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository; // 3. Inject Token Repo
    private final ModelMapper modelMapper;

    @Override
    @Transactional
    public UserDTO createUser(UserDTO userDTO) {
        if (userDTO.getEmail() == null || userDTO.getEmail().isBlank()) {
            throw new IllegalArgumentException("Email is required.");
        }

        if (userRepository.existsByEmail(userDTO.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }

        User user = modelMapper.map(userDTO, User.class);
        user.setProvider(userDTO.getProvider() != null ? userDTO.getProvider() : Provider.LOCAL);
        User savedUser = userRepository.save(user);

        return modelMapper.map(savedUser, UserDTO.class);
    }

    @Override
    public UserDTO getUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with given email id : " + email));

        return modelMapper.map(user, UserDTO.class);
    }

    @Override
    public UserDTO getUserById(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        return modelMapper.map(user, UserDTO.class);
    }

    @Override
    public UserDTO updateUser(UserDTO userDTO, Long userId) {
        User existingUser = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id : " + userId));

        existingUser.setName(userDTO.getName());
        existingUser.setImage(userDTO.getImage());
        existingUser.setProvider(userDTO.getProvider());
        // TODO: change password update logic
        existingUser.setPassword(userDTO.getPassword());
        existingUser.setEnable(userDTO.isEnable());
        existingUser.setUpdatedAt(Instant.now());

        User updatedUser = userRepository.save(existingUser);

        return modelMapper.map(updatedUser, UserDTO.class);
    }
    
    @Override
    @Transactional
    public void deleteUser(Long userId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentEmail = authentication.getName();

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id : " + userId));

        if (user.getEmail().equals(currentEmail)) {
            throw new RuntimeException("Operation denied: You cannot delete your own account.");
        }

        refreshTokenRepository.deleteByUser(user);

        userRepository.delete(user);
    }

    @Override
    public Iterable<UserDTO> getAllUsers() {
        return userRepository
                .findAll()
                .stream()
                .map(user -> modelMapper.map(user, UserDTO.class)).toList();
    }
}