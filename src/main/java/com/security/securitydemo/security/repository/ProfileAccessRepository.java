package com.security.securitydemo.security.repository;


import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.securitydemo.security.entity.ProfileAccess;

public interface ProfileAccessRepository
        extends JpaRepository<ProfileAccess, Long> {

    Optional<ProfileAccess> findByUsernameAndTargetProfileIdAndPermission(
            String username,
            Long targetProfileId,
            String permission
    );
}