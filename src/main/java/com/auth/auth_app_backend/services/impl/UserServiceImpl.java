package com.auth.auth_app_backend.services.impl;

import com.auth.auth_app_backend.dtos.UserDTO;
import com.auth.auth_app_backend.entities.Provider;
import com.auth.auth_app_backend.entities.User;
import com.auth.auth_app_backend.exceptions.ResourceNotFoundException;
import com.auth.auth_app_backend.helpers.UserHelper;
import com.auth.auth_app_backend.repositories.UserRepository;
import com.auth.auth_app_backend.services.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
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
    public UserDTO getUserById(String userId) {
        User user = userRepository.findById(UserHelper.parseUUID(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        return modelMapper.map(user, UserDTO.class);
    }

    @Override
    public UserDTO updateUser(UserDTO userDTO, String userId) {
        UUID uId = UserHelper.parseUUID(userId);

        User existingUser = userRepository.findById(uId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id : " + userId));

        //we are not going to change email id for this project.
        existingUser.setName(userDTO.getName());
        existingUser.setImage(userDTO.getImage());
        existingUser.setProvider(userDTO.getProvider());
        //TODO: change password update logic
        existingUser.setPassword(userDTO.getPassword());
        existingUser.setEnable(userDTO.isEnable());
        existingUser.setUpdatedAt(Instant.now());
        User updatedUser = userRepository.save(existingUser);

        return modelMapper.map(updatedUser, UserDTO.class);
    }

    @Override
    public void deleteUser(String userId) {
        UUID uId = UserHelper.parseUUID(userId);
        User user = userRepository.findById(uId).orElseThrow(() ->
                new ResourceNotFoundException("User not found witd id : " + userId));
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
