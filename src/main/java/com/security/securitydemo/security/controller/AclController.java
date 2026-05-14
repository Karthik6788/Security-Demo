package com.security.securitydemo.security.controller;


import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.securitydemo.security.dto.GrantAccessRequest;
import com.security.securitydemo.security.entity.ProfileAccess;
import com.security.securitydemo.security.repository.ProfileAccessRepository;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

@RestController
@RequestMapping("/acl")
public class AclController {

    private final ProfileAccessRepository profileAccessRepository;

    public AclController(
            ProfileAccessRepository profileAccessRepository
    ) {
        this.profileAccessRepository =
                profileAccessRepository;
    }

    @PostMapping("/grant")
    @PreAuthorize("hasRole('ADMIN')")
    public String grantAccess(
            @RequestBody GrantAccessRequest request
    ) {

        ProfileAccess access =
                new ProfileAccess(
                        request.getUsername(),
                        request.getTargetProfileId(),
                        request.getPermission()
                );

        profileAccessRepository.save(access);

        return "Access granted successfully";
    }
    
    @GetMapping("/user/profile/{userId}")
    @PreAuthorize("hasPermission(#userId, 'PROFILE_READ')")
    public String getProfile(
            @PathVariable Long userId
    ) {

        return "Access allowed for profile id: " + userId;
    }
}
