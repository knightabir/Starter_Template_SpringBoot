package com.starter.service.impl;

import com.starter.model.User;
import com.starter.service.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {

    @Autowired
    private JavaMailSender mailSender;
    @Autowired
    private Environment env;

    @Override
    @Async
    public void sendVerificationEmail(User user, String verificationToken) {
        String appUrl = env.getProperty("app.url");
        String url = appUrl + "/verify?token=" + verificationToken;

        String subject = "Please verify your email";
        String text = "Please click the link below to verify your email: " + url;

        sendEmail(user.getEmail(), subject, text);
    }

    @Override
    @Async
    public void sendPasswordResetEmail(User user, String resetToken) {
        String appUrl = env.getProperty("app.url");
        String url = appUrl + "/reset-password?token=" + resetToken;

        String subject = "Password Reset Request";
        String text = "Please click the link below to reset your password: " + url;

        sendEmail(user.getEmail(), subject, text);
    }

    @Override
    public void sendSuccessfulRegistrationEmail(User user) {
        String subject = "Registration Successful";
        String text = "Your registration has been successful!";

        sendEmail(user.getEmail(), subject, text);
    }

    @Override
    public void sendSuccessfulPasswordResetEmail(User user) {
        String subject = "Password Reset Successful";
        String text = "Your password has been reset successfully!";

        sendEmail(user.getEmail(), subject, text);
    }

    @Override
    public void sendSuccessfulEmailVerificationEmail(User user) {
        String subject = "Email Verification Successful";
        String text = "Your email has been verified successfully!";

        sendEmail(user.getEmail(), subject, text);
    }

    private void sendEmail(String email, String subject, String text) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("abir07sarkar@gmail.com");
        message.setTo(email);
        message.setSubject(subject);
        message.setText(text);
        mailSender.send(message);
    }

}
