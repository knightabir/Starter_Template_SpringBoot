package com.starter.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            log.info("Requesting endpoint {} from {}", request.getRequestURI(), request.getRemoteAddr());
            String jwt = parseJwt(request);
            if (jwt != null && jwtUtils.validateToken(jwt)) {
                String email = jwtUtils.extractEmail(jwt);

                if (email != null && userDetailsService != null) {
                    log.info("Validating token for user: {}", email);
                    UserDetails userDetails = userDetailsService.loadUserByUsername(email);
                    if (userDetails != null) {
                        log.info("User details found : {}", userDetails.getUsername());

                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    } else {
                        log.error("User details not found : {}", email);
                    }
                } else {
                    log.error("UserDetailsService is null");
                }
            }
        } catch (Exception e) {
            log.error("Cannot set user authentication : {}", e.getMessage());
        }
        filterChain.doFilter(request, response);
    }


    private String parseJwt(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        return StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ") ? authHeader.substring(7) : null;
    }
}
