package com.starter.service;

import com.starter.dto.EmailVerificationRequest;
import com.starter.dto.PasswordResetRequest;
import com.starter.dto.RegisterRequest;
import com.starter.exception.EmailAlreadyExistsException;
import com.starter.exception.InvalidTokenException;

public interface AuthService {
    void registrationRequest(RegisterRequest request) throws EmailAlreadyExistsException;

    void verifyEmail(EmailVerificationRequest request) throws InvalidTokenException;

    void forgetPasswordRequest(PasswordResetRequest request) throws EmailAlreadyExistsException;

    void resetPassword(PasswordResetRequest request) throws InvalidTokenException;
}
