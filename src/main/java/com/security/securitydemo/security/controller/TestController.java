package com.security.securitydemo.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import com.security.securitydemo.security.util.AdminOnly;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class TestController {

    @GetMapping("/test")
    public String test() {
    	return "Protected API Accessed";
    }
    
    @GetMapping("/user/test")
    public String userApi() {
        return "User API";
    }

    @GetMapping("/admin/test")
    public String adminApi() {
        return "Admin API";
    }
    
    @GetMapping("/admintest/test")
    @AdminOnly
    public String admintestapi() {
    	return "this will be accessed only by the admin";
    }
    
    @GetMapping("/user/{username}")
    @PreAuthorize("#username == authentication.name")
    public String getProfile(@PathVariable String username) {
        return "Profile of " + username;
    }
    
    
    @GetMapping("/admintest/userDeleteAuthrize")
    @PreAuthorize("hasAuthority('USER_DELETE')")
    public String adminUserDelete() {
    	return "this will be accessed only by the admin";
    }
}
