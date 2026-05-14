package com.security.securitydemo.security.config;

import java.io.Serializable;
import java.util.Optional;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import com.security.securitydemo.security.entity.User;
import com.security.securitydemo.security.repository.UserRepository;

@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private final UserRepository userRepository;

    public CustomPermissionEvaluator(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public boolean hasPermission(
            Authentication authentication,
            Object targetDomainObject,
            Object permission
    ) {

        if (authentication == null || permission == null) {
            return false;
        }

        boolean isAdmin = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(auth -> auth.equals("ROLE_ADMIN"));

        if (isAdmin) {
            return true;
        }

        String requiredPermission = permission.toString();

        if ("PROFILE_UPDATE".equals(requiredPermission)) {

            Long targetUserId =
                    Long.valueOf(targetDomainObject.toString());

            String authenticatedUsername =
                    authentication.getName();

            return isOwner(
                    authenticatedUsername,
                    targetUserId
            );
        }

        return false;
    }

    private boolean isOwner(
            String authenticatedUsername,
            Long targetUserId
    ) {

        Optional<User> optionalUser =
                userRepository.findById(targetUserId);

        if (optionalUser.isEmpty()) {
            return false;
        }

        User targetUser = optionalUser.get();

        return targetUser.getUsername()
                .equals(authenticatedUsername);
    }

    @Override
    public boolean hasPermission(
            Authentication authentication,
            Serializable targetId,
            String targetType,
            Object permission
    ) {
        return hasPermission(authentication, targetId, permission);
    }
}