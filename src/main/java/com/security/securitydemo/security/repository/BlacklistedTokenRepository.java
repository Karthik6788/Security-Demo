package com.security.securitydemo.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.securitydemo.security.entity.BlacklistedToken;

public interface BlacklistedTokenRepository
extends JpaRepository<BlacklistedToken, Long> {

boolean existsByToken(String token);
}