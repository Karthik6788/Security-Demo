package com.security.securitydemo.security.model;

public enum Permission {

    USER_READ,
    USER_CREATE,
    USER_UPDATE,
    USER_DELETE,

    PROFILE_READ,
    PROFILE_UPDATE,

    TOKEN_REVOKE,

    AUDIT_READ
}