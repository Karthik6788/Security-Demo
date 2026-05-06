package com.security.securitydemo.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.securitydemo.security.entity.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    
    void deleteByUsername(String username);
}
