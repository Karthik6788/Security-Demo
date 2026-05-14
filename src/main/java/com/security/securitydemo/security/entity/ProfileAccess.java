package com.security.securitydemo.security.entity;


import jakarta.persistence.*;

@Entity
public class ProfileAccess {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private Long targetProfileId;

    private String permission;

    public ProfileAccess() {
    }

    public ProfileAccess(
            String username,
            Long targetProfileId,
            String permission
    ) {
        this.username = username;
        this.targetProfileId = targetProfileId;
        this.permission = permission;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public Long getTargetProfileId() {
        return targetProfileId;
    }

    public String getPermission() {
        return permission;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setTargetProfileId(Long targetProfileId) {
        this.targetProfileId = targetProfileId;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }
}
