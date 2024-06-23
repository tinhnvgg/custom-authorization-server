package org.example.springboot3oauth2security;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SampleCache {
    private SampleCache() {}
    public static final Map<String, Long> LOCKDOWN_DURATION_CACHE = new ConcurrentHashMap<>();
    public static final Map<String, Integer> LOGIN_FAILURE_ATTEMPTS_CACHE = new ConcurrentHashMap<>();
    public static final Map<String, Instant> LAST_CHANGED_PASS_CACHE = new ConcurrentHashMap<>();
}
