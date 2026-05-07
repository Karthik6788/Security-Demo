package com.security.securitydemo.security.util;


import io.jsonwebtoken.*;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtil {

    private final String SECRET = "!@123mysecretkeyverysecretmyveryverystrongsecretkey1234567890";

    // GENERATE TOKEN
    public String generateToken(String username,String role) {

        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .compact();
    }

    // EXTRACT USERNAME
    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    //EXTRACT ROLE
    public String extractRole(String token) {
        return getClaims(token).get("role", String.class);
    }
    
    // VALIDATE TOKEN
    public boolean isValid(String token) {
        try {
            getClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private Claims getClaims(String token) {

        return Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token)
                .getBody();
    }
    
    public Date extractExpiration(String token) {
        return getClaims(token).getExpiration();
    }
}
