package com.security.securitydemo.security.dto;

import lombok.Data;

@Data
public class RefreshRequest {
    private String refreshToken;
}