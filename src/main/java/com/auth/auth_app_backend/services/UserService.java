package com.auth.auth_app_backend.services;

import com.auth.auth_app_backend.dtos.UserDTO;

public interface UserService {

    // create user
    UserDTO createUser(UserDTO userDTO);

    // get user by email
    UserDTO getUserByEmail(String email);

    // get user by id
    UserDTO getUserById(Long userId);

    // update user
    UserDTO updateUser(UserDTO userDTO, Long userId);

    // delete user
    void deleteUser(Long userId);

    // get all users
    Iterable<UserDTO> getAllUsers();
}