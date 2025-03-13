package com.starter.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Document
@Data
@AllArgsConstructor
@NoArgsConstructor
public class User {
    @Id
    private String id;
    private String email;
    private String firstName;
    private String lastName;
    private String password;
    private String verificationToken;
    private String role;
    private boolean emailVerified;
    private String resetToken;
    private Instant resetTokenExpiry;
    private long createdAt;
    private long updatedAt;
    private boolean isActive;
    private boolean isBanned;
    private boolean isDeleted;
}
