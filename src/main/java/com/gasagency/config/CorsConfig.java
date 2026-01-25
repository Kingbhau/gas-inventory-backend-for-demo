package com.gasagency.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * CORS Configuration for cross-origin requests from different networks
 * Supports connections from various networks (Airtel WiFi, mobile data, etc.)
 */
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Value("${app.cors.allowed-origins:http://localhost:4200}")
    private String allowedOrigins;

    @Value("${app.cors.allowed-methods:GET,POST,PUT,DELETE,OPTIONS}")
    private String allowedMethods;

    @Value("${app.cors.allowed-headers:Content-Type,Authorization,X-Requested-With,Accept}")
    private String allowedHeaders;

    @Value("${app.cors.max-age:3600}")
    private long maxAge;

    @Value("${app.cors.allow-credentials:true}")
    private boolean allowCredentials;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // Configure CORS for all API endpoints
        var corsConfig = registry.addMapping("/api/**")
                .allowedMethods(allowedMethods.split(","))
                .allowedHeaders("*") // Allow all headers for better compatibility
                .exposedHeaders("Authorization", "Content-Type", "X-Custom-Header") // Expose headers for mobile
                .maxAge(maxAge)
                .allowCredentials(allowCredentials);

        // Allow all origins for better network compatibility
        // This allows connections from any network (Airtel WiFi, mobile data, etc.)
        // Pattern matching: * matches all origins
        corsConfig.allowedOriginPatterns("*");
    }
}
