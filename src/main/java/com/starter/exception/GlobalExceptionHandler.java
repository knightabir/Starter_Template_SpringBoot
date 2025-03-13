package com.starter.exception;

import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.security.SignatureException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleEmailAlreadyExistsException(EmailAlreadyExistsException ex) {
        log.error("Email already exists: {}", ex.getMessage());
        return createErrorResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), ex.getMessage());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFoundException(UserNotFoundException ex) {
        log.error("User not found: {}", ex.getMessage());
        return createErrorResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), ex.getMessage());
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidTokenException(InvalidTokenException ex) {
        log.error("Invalid token: {}", ex.getMessage());
        return createErrorResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), ex.getMessage());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentialsException(BadCredentialsException ex) {
        log.error("Bad credentials : {}", ex.getMessage());
        return createErrorResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), ex.getMessage());
    }

    @ExceptionHandler({SignatureException.class, MalformedJwtException.class, UnsupportedJwtException.class})
    public ResponseEntity<ErrorResponse> handleJwtException(Exception ex) {
        log.error("JWT Exception: {}", ex.getMessage());
        return createErrorResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), ex.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ValidationErrorResponse> handleValidationException(MethodArgumentNotValidException ex) {
        if (ex == null) {
            log.error("Null MethodArgumentNotValidException");
            return new ResponseEntity<>(new ValidationErrorResponse(
                    LocalDateTime.now(),
                    HttpStatus.BAD_REQUEST.value(),
                    "Null MethodArgumentNotValidException",
                    Map.of("exception", "Null MethodArgumentNotValidException")), HttpStatus.BAD_REQUEST);
        }

        if (ex.getBindingResult() == null) {
            log.error("Null binding result");
            return new ResponseEntity<>(new ValidationErrorResponse(
                    LocalDateTime.now(),
                    HttpStatus.BAD_REQUEST.value(),
                    "Null binding result",
                    Map.of("exception", "Null binding result")), HttpStatus.BAD_REQUEST);
        }

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            if (error instanceof FieldError) {
                String fieldName = ((FieldError) error).getField();
                String errorMessage = error.getDefaultMessage();
                errors.put(fieldName, errorMessage);
            } else {
                log.error("Unexpected error: {}", error.toString());
            }
        });

        log.error("Validation exception: {}", errors);
        ValidationErrorResponse response = ValidationErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .message("Validation failed")
                .errors(errors)
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGlobalException(Exception ex) {
        if (ex == null) {
            log.error("Null exception");
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred. Please try again later.", "Null exception");
        }

        log.error("Unhandled Exception: {}", ex.getMessage());
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred. Please try again later.", "Required request body is missing: " + ex.getMessage().split(":")[0]);
    }

    private ResponseEntity<ErrorResponse> createErrorResponse(HttpStatus status, String message, String error) {
        if (status == null) {
            log.error("Null status");
            return new ResponseEntity<>(ErrorResponse.builder()
                    .timestamp(LocalDateTime.now())
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .error("Null status")
                    .message("An unexpected error occurred. Please try again later.")
                    .build(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        if (message == null) {
            log.error("Null message");
            return new ResponseEntity<>(ErrorResponse.builder()
                    .timestamp(LocalDateTime.now())
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .error("Null message")
                    .message("An unexpected error occurred. Please try again later.")
                    .build(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        if (error == null) {
            log.error("Null error");
            return new ResponseEntity<>(ErrorResponse.builder()
                    .timestamp(LocalDateTime.now())
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .error("Null error")
                    .message("An unexpected error occurred. Please try again later.")
                    .build(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        ErrorResponse errorResponse = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(status.value())
                .error(error)
                .message(message)
                .build();

        return new ResponseEntity<>(errorResponse, status);
    }
}
