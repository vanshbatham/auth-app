package com.auth.auth_app_backend.services;

import com.auth.auth_app_backend.dtos.UserDTO;

public interface UserService {
    //create user.
    UserDTO createUser(UserDTO userDTO);

    //get user by email.
    UserDTO getUserByEmail(String email);

    //get user by id.
    UserDTO getUserById(String userId);

    //update user.
    UserDTO updateUser(UserDTO userDTO, String userId);

    //delete user.
    void deleteUser(String userId);

    //get all users.
    Iterable<UserDTO> getAllUsers();


}
