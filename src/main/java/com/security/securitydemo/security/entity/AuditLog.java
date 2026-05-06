package com.security.securitydemo.security.entity;

import java.time.LocalDateTime;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Entity
@Setter
@Getter
public class AuditLog {

    @Id
    @GeneratedValue
    private Long id;

    private String username;

    private String action;

    private String ipAddress;

    private LocalDateTime timestamp;

    private String details;
}