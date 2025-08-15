package com.example.oauth_server.oauth_server.utils;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;

@Component
public class JwtUtil {

    @Value("${super-secret-key}")
    private String secret; // Spring will inject this

    private Key secretKey;
    private final long EXPIRATION_TIME = 864_000_000; // 10 days

    @PostConstruct
    public void init() {
        // Decode Base64 secret and generate Key
        byte[] keyBytes = Base64.getDecoder().decode(secret);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String userInfo) {
        return Jwts.builder()
                .claim("userInfo", userInfo)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(secretKey)
                .compact();
    }

    // Optional helper to extract claims or user info
    public String getUserInfoFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("userInfo", String.class);
    }
}
