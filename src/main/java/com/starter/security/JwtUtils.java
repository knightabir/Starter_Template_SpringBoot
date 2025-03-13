package com.starter.security;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
@Slf4j
public class JwtUtils {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expirationMs}")
    private int jwtExpirationMs;

    private SecretKey getSigningKey() {
        log.info("Retrieving signing key");
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public String extractEmail(String token) {
        log.info("Extracting username from token.");
        Claims claims = extractAllClaims(token);
        return claims.getSubject();
    }

    public Date extractExpiration(String token) {
        log.info("Extracting expiration date from token.");
        Claims claims = extractAllClaims(token);
        return claims.getExpiration();
    }

    private boolean isTokenExpired(String token) {
        log.info("Checking if token is expired.");
        Date expiration = extractExpiration(token);
        return expiration.before(new Date());
    }

    public Claims extractAllClaims(String token) {
        log.info("Extracting all claims for token.");
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String generateToken(String email) {
        log.info("Generating token for {}", email);
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, email);
    }

    private String createToken(Map<String, Object> claims, String email) {
        log.info("Creating token for subject {}", email);
        return Jwts.builder()
                .claims(claims)
                .subject(email)
                .header().empty().add("type", "JWT")
                .and()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(getSigningKey())
                .compact();
    }

    public Boolean validateToken(String token) {
        log.info("Validating token");
        return !isTokenExpired(token);
    }
}

