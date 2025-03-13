package com.starter.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PasswordResetRequest {

    @NotBlank(message = "Reset token is required.")
    private String token;

    @NotBlank(message = "New password is required.")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).{8,}$", message = "Password must contain at least one digit, one lowercase, one uppercase, and one special character")
    private String newPassword;

    @NotBlank(message = "Confirm password is required.")
    private String confirmNewPassword;
}
