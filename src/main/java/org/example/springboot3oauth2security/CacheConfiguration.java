package org.example.springboot3oauth2security;

import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableCaching
public class CacheConfiguration {
    // Jun 22, 2024: Currently using the default simple Spring Cache provider
}
