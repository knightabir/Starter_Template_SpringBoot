package com.starter.service.impl;

import com.starter.dto.ForgetPasswordRequest;
import com.starter.dto.PasswordResetRequest;
import com.starter.dto.RegisterRequest;
import com.starter.exception.EmailAlreadyExistsException;
import com.starter.exception.InvalidTokenException;
import com.starter.exception.UserNotFoundException;
import com.starter.model.User;
import com.starter.repository.UserRepository;
import com.starter.service.EmailService;
import com.starter.service.UserService;
import com.starter.util.RandomStringGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Service
@Slf4j
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private RandomStringGenerator tokenGenerator;
    @Autowired
    private EmailService emailService;

    @Override
    public void registerUser(RegisterRequest request) {
        log.info("Register user request: {}", request);
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Email already exists: {}", request.getEmail());
            throw new EmailAlreadyExistsException("Email already exists");
        }
        if (request.getEmail() == null || request.getPassword() == null) {
            log.warn("Email and password cannot be null. Request: {}", request);
            throw new IllegalArgumentException("Email and password cannot be null");
        }
        User user = new User();
        user.setEmail(request.getEmail());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole("USER");
        user.setActive(true);
        user.setBanned(false);
        user.setDeleted(false);
        user.setEmailVerified(false);
        user.setVerificationToken(tokenGenerator.generateRandomString(32));
        user.setResetToken(null);
        user.setUpdatedAt(0L);
        user.setResetTokenExpiry(null);
        user.setCreatedAt(System.currentTimeMillis());
        log.info("Saving user: {}", user);
        User savedUser = userRepository.save(user);

        log.info("Sending successful registration email to user: {}", user.getEmail());
        emailService.sendSuccessfulRegistrationEmail(user);

        log.info("Sending verification email to user: {}", user.getEmail());
        emailService.sendVerificationEmail(user, user.getVerificationToken());
    }

    @Override
    public void registerAdmin(RegisterRequest request) {
        log.info("Register user request: {}", request);
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Email already exists: {}", request.getEmail());
            throw new EmailAlreadyExistsException("Email already exists");
        }
        if (request.getEmail() == null || request.getPassword() == null) {
            log.warn("Email and password cannot be null. Request: {}", request);
            throw new IllegalArgumentException("Email and password cannot be null");
        }
        User user = new User();
        user.setEmail(request.getEmail());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole("ADMIN");
        user.setActive(true);
        user.setBanned(false);
        user.setDeleted(false);
        user.setEmailVerified(false);
        user.setVerificationToken(tokenGenerator.generateRandomString(32));
        user.setResetToken(null);
        user.setUpdatedAt(0L);
        user.setResetTokenExpiry(null);
        user.setCreatedAt(System.currentTimeMillis());
        log.info("Saving user: {}", user);
        User savedUser = userRepository.save(user);

        log.info("Sending successful registration email to user: {}", user.getEmail());
        emailService.sendSuccessfulRegistrationEmail(user);

        log.info("Sending verification email to user: {}", user.getEmail());
        emailService.sendVerificationEmail(user, user.getVerificationToken());
    }

    @Override
    public User findUserByEmail(String email) {
        log.debug("Attempting to find user by email: {}", email);
        User user = userRepository.findByEmail(email);
        if (user == null) {
            log.warn("User not found with email: {}", email);
            throw new UserNotFoundException("User not found");
        }
        log.debug("User found: {}", user);
        return user;
    }

    @Override
    public User findUserById(String id) {
        log.debug("Attempting to find user by id: {}", id);
        User user = userRepository.findById(id).orElse(null);
        if (user == null) {
            log.warn("User not found with id: {}", id);
            throw new UserNotFoundException("User not found");
        }
        log.debug("User found: {}", user);
        return user;
    }

    @Override
    public User updateUser(String id, RegisterRequest user) {
        if (id == null || user == null) {
            log.warn("ID or user is null. Request: {}", user);
            throw new IllegalArgumentException("ID and user cannot be null");
        }
        if (!userRepository.existsById(id)) {
            log.warn("User not found with id: {}", id);
            throw new UserNotFoundException("User not found");
        }
        if (user.getEmail() != null && !user.getEmail().equals(findUserById(id).getEmail())) {
            if (userRepository.existsByEmail(user.getEmail())) {
                log.warn("Email already exists: {}", user.getEmail());
                throw new EmailAlreadyExistsException("Email already exists");
            }
        }

        if (!Objects.equals(user.getPassword(), user.getConfirmPassword())) {
            log.warn("Passwords do not match. Request: {}", user);
            throw new IllegalArgumentException("Passwords do not match");
        }

        User existingUser = findUserById(id);
        existingUser.setUpdatedAt(System.currentTimeMillis());

        Optional.ofNullable(user.getFirstName()).ifPresent(existingUser::setFirstName);
        Optional.ofNullable(user.getLastName()).ifPresent(existingUser::setLastName);
        Optional.ofNullable(user.getPassword())
                .map(passwordEncoder::encode)
                .ifPresent(existingUser::setPassword);
        Optional.ofNullable(user.getEmail()).ifPresent(existingUser::setEmail);

        log.info("Updating user: {}", existingUser);
        return userRepository.save(existingUser);
    }

    @Override
    public void deleteUser(String userId) {
        log.debug("Start deleting user process for ID: {}", userId);
        try {
            User user = findUserById(userId);
            if (user == null) {
                log.error("User not found with ID: {}", userId);
                throw new UserNotFoundException("User not found");
            }
            log.debug("User found: {}", user);
            user.setDeleted(true);
            user.setUpdatedAt(System.currentTimeMillis());
            log.info("Marking user as deleted: {}", user);
            userRepository.save(user);
            log.debug("User successfully marked as deleted: {}", userId);
        } catch (UserNotFoundException e) {
            log.error("UserNotFoundException encountered: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error while deleting user with ID: {}: {}", userId, e.getMessage());
            throw e;
        } finally {
            log.debug("End deleting user process for ID: {}", userId);
        }
    }

    @Override
    public List<User> getAllUsers() {
        log.debug("Attempting to retrieve all users");
        List<User> users = userRepository.findAll();
        log.debug("Retrieved {} users", users.size());
        if (log.isTraceEnabled()) {
            log.trace("Retrieved users: {}", users);
        }
        return users;
    }

    @Override
    public List<User> getUserByRole(String role) {
        log.debug("Attempting to find users with role: {}", role);
        List<User> users = userRepository.findByRole(role);
        log.debug("Found {} users with role {}", users.size(), role);
        return users;
    }

    @Override
    public void emailVerification(String verificationToken) {
        log.debug("Starting email verification with token: {}", verificationToken);

        User user = userRepository.findByVerificationToken(verificationToken)
                .orElseThrow(() -> {
                    log.error("User not found with token: {}", verificationToken);
                    return new UserNotFoundException("User not found");
                });

        log.info("User found: {}. Verifying email...", user.getEmail());
        user.setEmailVerified(true);
        user.setUpdatedAt(System.currentTimeMillis());
        user.setVerificationToken(null);
        userRepository.save(user);
        log.info("Email successfully verified for user: {}", user.getEmail());

        log.info("Sending successful email verification email to user: {}", user.getEmail());
        emailService.sendSuccessfulEmailVerificationEmail(user);
    }

    @Override
    public void forgetPasswordRequest(ForgetPasswordRequest request) throws EmailAlreadyExistsException {
        log.debug("Received forget password request for email: {}", request.getEmail());

        User user = userRepository.findByEmail(request.getEmail());
        if (user == null) {
            log.warn("User not found with email: {}", request.getEmail());
            throw new UserNotFoundException("User not found");
        }

        log.debug("Generating reset token for user: {}", user.getEmail());
        user.setResetToken(tokenGenerator.generateRandomString(32));
        user.setResetTokenExpiry(Instant.now().plusSeconds(3600));
        userRepository.save(user);

        log.info("Sending password reset email to user: {}", user.getEmail());
        emailService.sendPasswordResetEmail(user, user.getResetToken());
    }

    @Override
    public void resetPassword(PasswordResetRequest request) throws InvalidTokenException {
        log.debug("Attempting to reset password for user with token: {}", request.getToken());
        User user = userRepository.findByResetToken(request.getToken())
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        log.info("Resetting password for user: {}", user.getEmail());

        if (user.getResetTokenExpiry().isBefore(Instant.now())) {
            log.warn("Token has expired for user: {}", user.getEmail());
            throw new InvalidTokenException("Token has expired");
        }

        if (!request.getNewPassword().equals(request.getConfirmNewPassword())) {
            log.warn("Passwords do not match for user: {}", user.getEmail());
            throw new IllegalArgumentException("Passwords do not match");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setResetToken(null);
        user.setResetTokenExpiry(null);
        user.setUpdatedAt(System.currentTimeMillis());
        userRepository.save(user);
        log.info("Password successfully reset for user: {}", user.getEmail());

        log.info("Sending successful password reset email to user: {}", user.getEmail());
        emailService.sendSuccessfulPasswordResetEmail(user);
    }


}
