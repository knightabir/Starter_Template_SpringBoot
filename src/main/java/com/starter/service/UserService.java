package com.starter.service;

import com.starter.dto.ForgetPasswordRequest;
import com.starter.dto.PasswordResetRequest;
import com.starter.dto.RegisterRequest;
import com.starter.exception.EmailAlreadyExistsException;
import com.starter.exception.InvalidTokenException;
import com.starter.model.User;

import java.util.List;

public interface UserService {
    void registerUser(RegisterRequest user);

    void registerAdmin(RegisterRequest user);

    User findUserByEmail(String email);

    User findUserById(String id);

    User updateUser(String userId, RegisterRequest user);

    void deleteUser(String userId);

    List<User> getAllUsers();

    List<User> getUserByRole(String role);

    void emailVerification(String verificationToken);

    void forgetPasswordRequest(ForgetPasswordRequest request) throws EmailAlreadyExistsException;

    void resetPassword(PasswordResetRequest request) throws InvalidTokenException;


}
