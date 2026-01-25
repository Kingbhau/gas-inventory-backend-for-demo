package com.gasagency.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import java.util.Arrays;

/**
 * CORS Configuration for cross-origin requests from different networks
 * Supports connections from various networks (Airtel WiFi, mobile data, etc.)
 * Uses a custom CORS filter for maximum compatibility without limitations
 */
@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Allow all origins - works from any network (Airtel WiFi, mobile data, VPN,
        // etc.)
        // When allowCredentials is true, we can't use "*", so we use a pattern instead
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));

        // Allow all HTTP methods
        configuration.setAllowedMethods(Arrays.asList("*"));

        // Allow all headers
        configuration.setAllowedHeaders(Arrays.asList("*"));

        // Expose important headers
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Custom-Header",
                "X-Total-Count",
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials"));

        // Allow credentials (tokens, cookies) in cross-origin requests
        configuration.setAllowCredentials(true);

        // Cache preflight response for 1 hour
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Register CORS for all API endpoints
        source.registerCorsConfiguration("/api/**", configuration);
        // Also register for auth endpoints
        source.registerCorsConfiguration("/auth/**", configuration);
        // Register for all endpoints as fallback
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    @Bean
    public CorsFilter corsFilter(CorsConfigurationSource corsConfigurationSource) {
        return new CorsFilter(corsConfigurationSource);
    }
}
