package com.security.securitydemo.service;

import java.time.LocalDateTime;

import org.springframework.stereotype.Service;

import com.security.securitydemo.security.entity.AuditAction;
import com.security.securitydemo.security.entity.AuditLog;
import com.security.securitydemo.security.repository.AuditLogRepository;

@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }
    public void log(String username, AuditAction action,String ip,String details) {

    	AuditLog log = new AuditLog();

    	log.setUsername(username);
    	log.setAction(action.name());
    	log.setIpAddress(ip);
    	log.setTimestamp(LocalDateTime.now());
    	log.setDetails(details);

    	auditLogRepository.save(log);
}
    

}
