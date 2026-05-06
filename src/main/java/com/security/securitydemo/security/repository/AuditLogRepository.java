package com.security.securitydemo.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.securitydemo.security.entity.AuditLog;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
}