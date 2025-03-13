package com.starter.repository;

import com.starter.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {
    User findByEmail(String email);

    boolean existsByEmail(String email);

    List<User> findByRole(String role);

    Optional<User> findByVerificationToken(String token);

    Optional<User> findByResetToken(String token);
}
