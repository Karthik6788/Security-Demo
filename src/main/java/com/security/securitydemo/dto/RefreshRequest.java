package com.security.securitydemo.dto;

import lombok.Data;

@Data
public class RefreshRequest {
    private String refreshToken;
}