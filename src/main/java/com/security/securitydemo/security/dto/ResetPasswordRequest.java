package com.security.securitydemo.security.dto;

import lombok.Data;

@Data
public class ResetPasswordRequest {

    private String token;
    private String newPassword;
}