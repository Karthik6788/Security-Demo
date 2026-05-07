package com.security.securitydemo.security.service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import com.security.securitydemo.security.model.RateLimitInfo;

@Service
public class RateLimitService {

    private final Map<String, RateLimitInfo> requests = new ConcurrentHashMap<>();

    private static final int MAX_REQUESTS = 10;
    private static final long WINDOW_MINUTES = 1;
    
    public boolean isAllowed(String ip,String endpoint) {
    	
    	String key = ip + ":" + endpoint;
    	ip=key;

        LocalDateTime now = LocalDateTime.now();

        RateLimitInfo info = requests.get(ip);

        if (info == null) {
            requests.put(ip, new RateLimitInfo(1, now));
            return true;
        }
        
        if (info.getWindowStart()
                .plusMinutes(WINDOW_MINUTES)
                .isBefore(now)) {

            info.setCount(1);
            info.setWindowStart(now);

            return true;
        }
        
        if (info.getCount() >= MAX_REQUESTS) {
            return false;
        }

        info.setCount(info.getCount() + 1);

        return true;
    
    } 
}
