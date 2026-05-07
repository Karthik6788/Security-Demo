package com.security.securitydemo.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.securitydemo.security.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
}