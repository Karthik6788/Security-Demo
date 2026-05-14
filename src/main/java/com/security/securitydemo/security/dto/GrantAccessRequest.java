package com.security.securitydemo.security.dto;


public class GrantAccessRequest {

    private String username;

    private Long targetProfileId;

    private String permission;

    public GrantAccessRequest() {
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Long getTargetProfileId() {
        return targetProfileId;
    }

    public void setTargetProfileId(Long targetProfileId) {
        this.targetProfileId = targetProfileId;
    }

    public String getPermission() {
        return permission;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }
}