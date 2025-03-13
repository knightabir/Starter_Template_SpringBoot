package com.starter.service;

import com.starter.model.User;

public interface EmailService {
    void sendVerificationEmail(User user, String verificationToken);

    void sendPasswordResetEmail(User user, String resetToken);

    void sendSuccessfulRegistrationEmail(User user);

    void sendSuccessfulPasswordResetEmail(User user);

    void sendSuccessfulEmailVerificationEmail(User user);
}
