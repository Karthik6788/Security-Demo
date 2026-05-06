package com.security.securitydemo.model;

import java.time.LocalDateTime;

public class RateLimitInfo {

    private int count;
    private LocalDateTime windowStart;

    public RateLimitInfo(int count, LocalDateTime windowStart) {
        this.count = count;
        this.windowStart = windowStart;
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }

    public LocalDateTime getWindowStart() {
        return windowStart;
    }

    public void setWindowStart(LocalDateTime windowStart) {
        this.windowStart = windowStart;
    }
}