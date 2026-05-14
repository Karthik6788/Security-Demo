package com.security.securitydemo.security.config;

import java.io.Serializable;
import java.util.Optional;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import com.security.securitydemo.security.entity.ProfileAccess;
import com.security.securitydemo.security.entity.User;
import com.security.securitydemo.security.repository.ProfileAccessRepository;
import com.security.securitydemo.security.repository.UserRepository;

@Component
public class CustomPermissionEvaluator
        implements PermissionEvaluator {

    private final UserRepository userRepository;

    private final ProfileAccessRepository profileAccessRepository;

    public CustomPermissionEvaluator(
            UserRepository userRepository,
            ProfileAccessRepository profileAccessRepository
    ) {
        this.userRepository = userRepository;
        this.profileAccessRepository = profileAccessRepository;
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

        String authenticatedUsername =
                authentication.getName();

        String requiredPermission =
                permission.toString();

        Long targetProfileId =
                Long.valueOf(targetDomainObject.toString());

        if (isAdmin(authentication)) {
            return true;
        }

        if (isOwner(authenticatedUsername, targetProfileId)) {
            return true;
        }

        if (hasAclPermission(
                authenticatedUsername,
                targetProfileId,
                requiredPermission
        )) {
            return true;
        }

        return false;
    }

    private boolean isAdmin(Authentication authentication) {

        return authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(auth -> auth.equals("ROLE_ADMIN"));
    }

    private boolean isOwner(
            String authenticatedUsername,
            Long targetProfileId
    ) {

        Optional<User> optionalUser =
                userRepository.findById(targetProfileId);

        if (optionalUser.isEmpty()) {
            return false;
        }

        User targetUser = optionalUser.get();

        return targetUser.getUsername()
                .equals(authenticatedUsername);
    }

    private boolean hasAclPermission(
            String username,
            Long targetProfileId,
            String permission
    ) {

        Optional<ProfileAccess> access =
                profileAccessRepository
                        .findByUsernameAndTargetProfileIdAndPermission(
                                username,
                                targetProfileId,
                                permission
                        );

        return access.isPresent();
    }

    @Override
    public boolean hasPermission(
            Authentication authentication,
            Serializable targetId,
            String targetType,
            Object permission
    ) {

        return hasPermission(
                authentication,
                targetId,
                permission
        );
    }
}