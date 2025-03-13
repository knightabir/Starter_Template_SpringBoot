package com.starter.service.impl;

import com.starter.dto.EmailVerificationRequest;
import com.starter.dto.PasswordResetRequest;
import com.starter.dto.RegisterRequest;
import com.starter.exception.EmailAlreadyExistsException;
import com.starter.exception.InvalidTokenException;
import com.starter.service.AuthService;
import com.starter.service.EmailService;
import com.starter.service.UserService;
import com.starter.util.RandomStringGenerator;
import lombok.extern.slf4j.Slf4j;
import lombok.extern.slf4j.XSlf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AuthServiceImpl implements AuthService {

    @Autowired
    private UserService userService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RandomStringGenerator tokenGenerator;

    @Override
    public void registrationRequest(RegisterRequest request) throws EmailAlreadyExistsException {
        userService.registerUser(request);
    }

    @Override
    public void verifyEmail(EmailVerificationRequest request) throws InvalidTokenException {

    }

    @Override
    public void forgetPasswordRequest(PasswordResetRequest request) throws EmailAlreadyExistsException {

    }

    @Override
    public void resetPassword(PasswordResetRequest request) throws InvalidTokenException {

    }
}
