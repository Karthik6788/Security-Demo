package com.security.securitydemo.security.service;

import com.security.securitydemo.security.dto.AuthResponse;
import com.security.securitydemo.security.dto.RefreshRequest;
import com.security.securitydemo.security.entity.AuditAction;
import com.security.securitydemo.security.entity.BlacklistedToken;
import com.security.securitydemo.security.entity.PasswordResetToken;
import com.security.securitydemo.security.entity.RefreshToken;
import com.security.securitydemo.security.entity.Role;
import com.security.securitydemo.security.entity.User;
import com.security.securitydemo.security.repository.BlacklistedTokenRepository;
import com.security.securitydemo.security.repository.PasswordResetTokenRepository;
import com.security.securitydemo.security.repository.RefreshTokenRepository;
import com.security.securitydemo.security.repository.UserRepository;
import com.security.securitydemo.security.util.JwtUtil;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {
	private final JwtUtil jwtUtil;


    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuditService auditService;
    private final BlacklistedTokenRepository blacklistedTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;

    private static final int MAX_FAILED_ATTEMPTS = 5;

    private static final long LOCK_DURATION_MINUTES = 15;
    // REGISTER
    public void register(String username, String password) {

        // 1. check if user already exists
        Optional<User> existingUser = userRepository.findByUsername(username);

        if (existingUser.isPresent()) {
            throw new RuntimeException("User already exists");
        }

        // 2. hash password
        String hashedPassword = passwordEncoder.encode(password);

        // 3. create user
        User user = new User();
        user.setUsername(username);
        user.setPassword(hashedPassword);
        user.setRole(Role.USER);   //setting the role

        // 4. save user
        userRepository.save(user);
    }

    private boolean unlockWhenTimeExpired(User user) {

        if (user.getLockTime() == null) {
            return false;
        }

        return user.getLockTime()
                .plusMinutes(LOCK_DURATION_MINUTES)
                .isBefore(LocalDateTime.now());
    }
    
    private void increaseFailedAttempts(User user) {

        int attempts = user.getFailedAttempts() + 1;

        user.setFailedAttempts(attempts);

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            user.setAccountLocked(true);
            user.setLockTime(LocalDateTime.now());
        }

        userRepository.save(user);
    }
    
    // LOGIN
    public AuthResponse login(String username, String password,String ip) {

//        // 1. fetch user
//        User user = userRepository.findByUsername(username)
//                .orElseThrow(() -> new RuntimeException("User not found"));
//
//        // 2. verify password
//        boolean isMatch = passwordEncoder.matches(password, user.getPassword());
//
//        if (!isMatch) {
//            throw new RuntimeException("Invalid password");
//        }
//
//        // 3. return user (later we generate JWT here)
//        return user;
    	
//    	User user = userRepository.findByUsername(username)
//                .orElseThrow(() -> new RuntimeException("User not found"));
//
//        if (!passwordEncoder.matches(password, user.getPassword())) {
//            throw new RuntimeException("Invalid password");
//        }
//
//        // 🔥 generate token instead of returning user
//        return jwtUtil.generateToken(user.getUsername(),user.getRole().toString());
    	
    	 User user = userRepository.findByUsername(username)
    	            .orElseThrow(() -> new RuntimeException("User not found"));

    	 		if (user.isAccountLocked()) {
    	 			if (unlockWhenTimeExpired(user)) {
    	 				user.setAccountLocked(false);
    	 				user.setFailedAttempts(0);
    	 				user.setLockTime(null);
    	 				auditService.log(
    	 					    user.getUsername(),
    	 					    AuditAction.ACCOUNT_LOCKED,
    	 					    ip,
    	 					    "Exceeded failed attempts"
    	 					);
    	 				userRepository.save(user);
    		    } 
    	 		else {
    		        throw new RuntimeException("Account locked. Try later.");
    		    }
    		}
    	    if (!passwordEncoder.matches(password, user.getPassword())) {
    	    	increaseFailedAttempts(user);
    	    	
    	    	auditService.log(
    	    		    username,
    	    		    AuditAction.LOGIN_FAILED,
    	    		    ip,
    	    		    "Invalid password"
    	    		);
    	        throw new RuntimeException("Invalid password");
    	    }

    	    String accessToken = jwtUtil.generateToken(user.getUsername(), user.getRole().name());
    	    String refreshToken = createRefreshToken(user.getUsername());

    	    user.setFailedAttempts(0);
    	    user.setAccountLocked(false);
    	    user.setLockTime(null);
    	    
    	    userRepository.save(user);
    	    
    	    auditService.log(
    	    	    username,
    	    	    AuditAction.LOGIN_SUCCESS,
    	    	    ip,
    	    	    "User authenticated"
    	    	);
    	    return new AuthResponse(accessToken, refreshToken);
    }
    
    public String createRefreshToken(String username) {

        String token = UUID.randomUUID().toString();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(token);
        refreshToken.setUsername(username);
        refreshToken.setExpiryDate(
                new Date(System.currentTimeMillis() + 7 * 24 * 60 * 60 * 1000)
        );

        refreshTokenRepository.save(refreshToken);

        return token;
    }
    
    @Transactional(dontRollbackOn  = RuntimeException.class)
    public AuthResponse refresh(RefreshRequest request,String ip) {

    	RefreshToken token = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        // 1. check expiry
        if (token.getExpiryDate().before(new Date())) {
            throw new RuntimeException("Refresh token expired");
        }

        if (token.isUsed()) {
            refreshTokenRepository.deleteByUsername(token.getUsername());

            auditService.log(
                    token.getUsername(),
                    AuditAction.TOKEN_REUSE_DETECTED,
                    ip,
                    "Refresh token replay attack suspected"
            );

            throw new RuntimeException(
                    "Refresh token reuse detected. Please login again."
            );
        }
        
        String username = token.getUsername();

        token.setUsed(true);
        refreshTokenRepository.save(token);
//        // 🔥 2. DELETE old token
//        refreshTokenRepository.delete(token);

        // 🔥 3. CREATE new refresh token
        String newRefreshToken = createRefreshToken(username);

        // 🔥 4. FETCH role properly
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String newAccessToken =
                jwtUtil.generateToken(
                        user.getUsername(),
                        user.getRole().name()
                );
        
        auditService.log(
        	    username,
        	    AuditAction.TOKEN_REFRESH,
        	    ip,
        	    "Refresh token rotated"
        	);

        return new AuthResponse(newAccessToken, newRefreshToken);
    }
    
    @Transactional
    public void logout(String token,String ip) {

        BlacklistedToken blacklistedToken = new BlacklistedToken();

        blacklistedToken.setToken(token);
        blacklistedToken.setExpiryDate(
                jwtUtil.extractExpiration(token)
        );
        
        String username=jwtUtil.extractUsername(token);

        auditService.log(
        	    username,
        	    AuditAction.LOGOUT,
        	    ip,
        	    "Token blacklisted"
        	);
        
        refreshTokenRepository.deleteByUsername(username);
        blacklistedTokenRepository.save(blacklistedToken);
    }
    
    public String requestPasswordReset(String username) {

        if (userRepository.findByUsername(username).isEmpty()) {
            return "If account exists, reset link sent";
        }

        passwordResetTokenRepository.deleteByUsername(username);

        String token = UUID.randomUUID().toString();

        PasswordResetToken resetToken =
                new PasswordResetToken();

        resetToken.setUsername(username);
        resetToken.setToken(token);
        resetToken.setExpiryTime(
                LocalDateTime.now().plusMinutes(15)
        );

        passwordResetTokenRepository.save(resetToken);

        return token;
    }
    
    @Transactional
    public void resetPassword(String token,String newPassword) {
    	PasswordResetToken resetToken =passwordResetTokenRepository.findByToken(token)
    		        .orElseThrow(() ->
    		            new RuntimeException("Invalid reset token"));
    	
    	if (resetToken.getExpiryTime()
    	        .isBefore(LocalDateTime.now())) {
    		throw new RuntimeException("token expired");
    	}
    	
    	User user = userRepository
    		    .findByUsername(resetToken.getUsername()).orElseThrow(() ->
	            new RuntimeException("User Not found"));
    	
    	user.setPassword(
    		    passwordEncoder.encode(newPassword)
    		);
    	
    	userRepository.save(user);
    	
    	passwordResetTokenRepository.delete(resetToken);
    	
    }
    
    
}
