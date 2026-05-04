package com.security.securitydemo.security.entity;

import java.util.Date;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Entity
@Setter
@Getter
public class BlacklistedToken {

    @Id
    @GeneratedValue
    private Long id;

    private String token;

    private Date expiryDate;
}
