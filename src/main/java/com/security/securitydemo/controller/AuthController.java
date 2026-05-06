package com.security.securitydemo.controller;


import com.security.securitydemo.dto.AuthResponse;
import com.security.securitydemo.dto.LoginRequest;
import com.security.securitydemo.dto.RefreshRequest;
import com.security.securitydemo.entity.User;
import com.security.securitydemo.security.entity.RefreshToken;
import com.security.securitydemo.security.repository.RefreshTokenRepository;
import com.security.securitydemo.service.RateLimitService;
import com.security.securitydemo.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import java.util.Date;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private RefreshTokenRepository refreshTokenRepository;
    private final RateLimitService rateLimitService;

    // REGISTER
    @PostMapping("/register")
    public String register(@RequestBody LoginRequest loginrequest) {

        userService.register(loginrequest.getUsername(), loginrequest.getPassword());
        return "User registered successfully";
    }

    // LOGIN
    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest loginrequest,HttpServletRequest httpRequest) {

//    	System.out.print(loginrequest.getUsername());
//        User user = userService.login(loginrequest.getUsername(), loginrequest.getPassword());
//        return "Login successful for user: " + user.getUsername();
    	String ip = httpRequest.getRemoteAddr();
    	if (!rateLimitService.isAllowed(ip)) {
    	    throw new RuntimeException("Too many requests");
    	}
    	
    	return userService.login(loginrequest.getUsername(), loginrequest.getPassword());
    }
    
    @GetMapping("/test")
    public String test() {
    	return "Protected API Accessed";
    }
    
    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestBody RefreshRequest request) {
        return userService.refresh(request);
    }
    
    @PostMapping("/logout")
    public String logout(HttpServletRequest request) {

        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {

            String token = header.substring(7);

            userService.logout(token);

            return "Logged out successfully";
        }

        throw new RuntimeException("Token missing");
    }
}