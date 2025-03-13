package com.starter.controller;

import com.starter.dto.*;
import com.starter.exception.EmailAlreadyExistsException;
import com.starter.exception.InvalidTokenException;
import com.starter.exception.UserNotFoundException;
import com.starter.model.User;
import com.starter.security.JwtUtils;
import com.starter.service.UserService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/api/v1/auth")
@Slf4j
public class AuthController {

    @Autowired
    private UserService userService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtils jwtUtils;

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@Valid @RequestBody RegisterRequest request) {
        Map<String, Object> response = new HashMap<>();
        if (request == null) {
            log.warn("Request is null");
            response.put("message", "Request cannot be null");
            return ResponseEntity.badRequest().body(response);
        }
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            log.warn("Password and confirm password do not match");
            response.put("message", "Password and confirm password do not match");
            return ResponseEntity.badRequest().body(response);
        }
        try {
            userService.registerUser(request);
            response.put("message", "User registered successfully");
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (Exception e) {
            log.error("Exception occurred during user registration: {}", e.getMessage());
            throw new EmailAlreadyExistsException(e.getMessage());
        }
    }

    @PostMapping("/register-admin")
    public ResponseEntity<?> registerAdmin(@Valid @RequestBody RegisterRequest request) {
        if (request == null) {
            log.warn("Request is null");
            return ResponseEntity.badRequest().body("Request cannot be null");
        }
        try {
            userService.registerAdmin(request);
            return ResponseEntity.status(HttpStatus.CREATED).body("Admin registered successfully");
        } catch (Exception e) {
            log.error("Exception occurred during admin registration: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginRequest request) {
        Map<String, Object> response = new HashMap<>();
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            Objects.requireNonNull(request.getEmail()),
                            Objects.requireNonNull(request.getPassword())
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateToken(authentication.getName());

            User user = userService.findUserByEmail(authentication.getName());
            if (user == null) {
                response.put("status", false);
                response.put("error", "User not found");
                response.put("code", HttpStatus.UNAUTHORIZED.value());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
            if (!user.isEmailVerified()) {
                response.put("status", false);
                response.put("error", "Please verify your email first");
                response.put("code", HttpStatus.UNAUTHORIZED.value());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            response.put("status", true);
            response.put("accessToken", jwt);
            response.put("email", authentication.getName());
            response.put("firstName", user.getFirstName());
            response.put("lastName", user.getLastName());
            response.put("isEmailVerified", user.isEmailVerified());
            response.put("code", HttpStatus.OK.value());

            return ResponseEntity.ok(response);
        } catch (NullPointerException e) {
            log.error("Login failed due to null pointer exception: {}", e.getMessage());
            response.put("status", false);
            response.put("error", "Invalid login request");
            response.put("code", HttpStatus.UNAUTHORIZED.value());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        } catch (Exception e) {
            log.error("Login failed: {}", e.getMessage());
            response.put("status", false);
            response.put("error", e.getMessage());
            response.put("code", HttpStatus.UNAUTHORIZED.value());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    @PostMapping("/forget-password")
    public ResponseEntity<?> forgetPassword(@Valid @RequestBody ForgetPasswordRequest request) {
        try {
            userService.forgetPasswordRequest(request);
            return ResponseEntity.ok("Password reset email sent successfully");
        } catch (Exception e) {
            log.error("Error occurred while sending password reset email: {}", e.getMessage());
            if (e instanceof NullPointerException) {
                return ResponseEntity.badRequest().body("User not found");
            } else {
                return ResponseEntity.badRequest().body("Something went wrong");
            }
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody PasswordResetRequest request) {
        try {
            userService.resetPassword(request);
            return ResponseEntity.ok("Password reset successfully");
        } catch (InvalidTokenException e) {
            log.error("Invalid token: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token");
        } catch (IllegalArgumentException e) {
            log.error("Invalid request: {}", e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error occurred during password reset: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred");
        }
    }

    @PostMapping("/verify-email")
    public ResponseEntity<Map<String,Object>> verifyEmail(@Valid @RequestParam String token) {
        Map<String,Object> response = new HashMap<>();
        try {
            if (token == null || token.isEmpty()) {
                response.put("status", false);
                response.put("code", HttpStatus.BAD_REQUEST.value());
                response.put("error", "Invalid token");
                return ResponseEntity.badRequest().body(response);
            }

            userService.emailVerification(token);
            response.put("status", true);
            response.put("code", HttpStatus.OK.value());
            response.put("message", "Email verified successfully");
            return ResponseEntity.ok(response);
        } catch (UserNotFoundException e) {
            log.error("User not found for token: {}", token);
            response.put("status", false);
            response.put("code", HttpStatus.NOT_FOUND.value());
            response.put("error", "User not found");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        } catch (InvalidTokenException e) {
            log.error("Invalid token: {}", e.getMessage());
            response.put("status", false);
            response.put("code", HttpStatus.UNAUTHORIZED.value());
            response.put("error", "Invalid or expired token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        } catch (Exception e) {
            log.error("Unexpected error occurred during email verification: {}", e.getMessage());
            response.put("status", false);
            response.put("code", HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.put("error", "An unexpected error occurred");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}
