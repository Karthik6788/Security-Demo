package com.security.securitydemo.security.entity;

import java.util.Set;

import com.security.securitydemo.security.model.Permission;

public enum Role {

    USER(
            Set.of(
                    Permission.PROFILE_READ,
                    Permission.PROFILE_UPDATE
            )
    ),

    ADMIN(
            Set.of(
                    Permission.USER_READ,
                    Permission.USER_CREATE,
                    Permission.USER_UPDATE,
                    Permission.USER_DELETE,
                    Permission.PROFILE_READ,
                    Permission.PROFILE_UPDATE,
                    Permission.TOKEN_REVOKE,
                    Permission.AUDIT_READ
            )
    );

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }
}
