package com.starter.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@Component
@Slf4j
public class RandomStringGenerator {

    private static final String CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String CHAR_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String CHAR_NUM = "0123456789";
    private static final String DATA_FOR_RANDOM = CHAR_LOWER + CHAR_UPPER + CHAR_NUM;
    private static final SecureRandom random = new SecureRandom();

    public String generateRandomString(int length) {
        log.info("Generating a random string with length {}", length);
        if (length < 1) throw new IllegalArgumentException("Length must be positive");

        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int rndCharAt = random.nextInt(DATA_FOR_RANDOM.length());
            int rndChar = DATA_FOR_RANDOM.charAt(rndCharAt);
            sb.append(rndChar);
        }
        log.info("Random string generated: {}", sb.toString());
        return sb.toString();
    }
}
