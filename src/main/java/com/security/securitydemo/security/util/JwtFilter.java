package com.security.securitydemo.security.util;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.security.securitydemo.security.entity.Role;
import com.security.securitydemo.security.repository.BlacklistedTokenRepository;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
@AllArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final BlacklistedTokenRepository blacklistedTokenRepository;


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {

            String token = header.substring(7);
            
            if (blacklistedTokenRepository.existsByToken(token)) {
                filterChain.doFilter(request, response);
                return;
            }

            if (jwtUtil.isValid(token)) {

            	String username = jwtUtil.extractUsername(token);
                String roleName = jwtUtil.extractRole(token);

                Role role = Role.valueOf(roleName);

                List<SimpleGrantedAuthority> authorities = new ArrayList<>();

                authorities.add(
                        new SimpleGrantedAuthority("ROLE_" + role.name())
                );

                role.getPermissions().forEach(permission ->
                        authorities.add(
                                new SimpleGrantedAuthority(permission.name())
                        )
                );

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(
                                username,
                                null,
                                authorities
                        );

                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }

        filterChain.doFilter(request, response);
    }
}
