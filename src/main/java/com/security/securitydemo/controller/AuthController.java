package com.security.securitydemo.controller;


import com.security.securitydemo.dto.AuthResponse;
import com.security.securitydemo.dto.ForgotPasswordRequest;
import com.security.securitydemo.dto.LoginRequest;
import com.security.securitydemo.dto.RefreshRequest;
import com.security.securitydemo.dto.ResetPasswordRequest;
import com.security.securitydemo.entity.User;
import com.security.securitydemo.security.entity.AuditAction;
import com.security.securitydemo.security.entity.RefreshToken;
import com.security.securitydemo.security.repository.RefreshTokenRepository;
import com.security.securitydemo.service.AuditService;
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
    private final RateLimitService rateLimitService;
    private final AuditService auditService;

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
    	if (!rateLimitService.isAllowed(ip,"login")) {   		
    		auditService.log(
    			    null,
    			    AuditAction.RATE_LIMIT_EXCEEDED,
    			    ip,
    			    "Too many requests"
    			);
    	    throw new RuntimeException("Too many requests");
    	}
    	
    	return userService.login(loginrequest.getUsername(), loginrequest.getPassword(),ip);
    }
    
    @GetMapping("/test")
    public String test() {
    	return "Protected API Accessed";
    }
    
    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestBody RefreshRequest request,HttpServletRequest httprequest) {
        return userService.refresh(request,httprequest.getRemoteAddr());
    }
    
    @PostMapping("/logout")
    public String logout(HttpServletRequest request) {

        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {

            String token = header.substring(7);

            userService.logout(token,request.getRemoteAddr());

            return "Logged out successfully";
        }

        throw new RuntimeException("Token missing");
    }
    
    
    @PostMapping("/forgot-password")
    public String forgotPassword(
            @RequestBody ForgotPasswordRequest request
    ) {
        return userService.requestPasswordReset(
                request.getUsername()
        );
    }
    
    @PostMapping("/reset-password")
    public String resetPassword(@RequestBody ResetPasswordRequest request) {
    	userService.resetPassword(request.getToken(),request.getNewPassword());
    	return "Password reset successful";
    			
    }
}