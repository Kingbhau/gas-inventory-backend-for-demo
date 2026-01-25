package com.gasagency.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.Arrays;

/**
 * CORS Configuration for cross-origin requests from different networks
 * Supports connections from various networks (Airtel WiFi, mobile data, etc.)
 * Uses a custom CORS configuration source for maximum compatibility
 */
@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Allow all origins - works from any network (Airtel WiFi, mobile data, VPN,
        // etc.)
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));

        // Allow all HTTP methods
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"));

        // Allow all headers
        configuration.setAllowedHeaders(Arrays.asList("*"));

        // Expose important headers
        configuration
                .setExposedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Custom-Header", "X-Total-Count"));

        // Allow credentials (tokens, cookies) in cross-origin requests
        configuration.setAllowCredentials(true);

        // Cache preflight response for 1 hour
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Register CORS for all API endpoints
        source.registerCorsConfiguration("/api/**", configuration);

        return source;
    }
}
