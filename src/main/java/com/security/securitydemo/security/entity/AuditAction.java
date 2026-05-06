package com.security.securitydemo.security.entity;

public enum AuditAction {
    LOGIN_SUCCESS,
    LOGIN_FAILED,
    LOGOUT,
    TOKEN_REFRESH,
    ACCOUNT_LOCKED,
    RATE_LIMIT_EXCEEDED,
    BLACKLIST_REJECTED
}