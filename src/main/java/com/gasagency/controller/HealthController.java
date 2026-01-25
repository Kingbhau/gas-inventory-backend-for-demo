package com.gasagency.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.HashMap;
import java.util.Map;

/**
 * Health Check Controller
 * Provides endpoint to verify backend connectivity from any network
 */
@RestController
@RequestMapping("/api/health")
public class HealthController {

    /**
     * Simple health check endpoint - no authentication required
     * Returns basic system information
     */
    @GetMapping
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("message", "Backend is accessible");
        response.put("timestamp", System.currentTimeMillis());
        response.put("version", "1.0");
        return ResponseEntity.ok(response);
    }

    /**
     * Detailed health check endpoint
     */
    @GetMapping("/detailed")
    public ResponseEntity<Map<String, Object>> healthDetailed() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("message", "Backend is running");
        response.put("timestamp", System.currentTimeMillis());
        response.put("memory", Runtime.getRuntime().totalMemory());
        response.put("availableMemory", Runtime.getRuntime().freeMemory());
        response.put("processorsAvailable", Runtime.getRuntime().availableProcessors());
        return ResponseEntity.ok(response);
    }
}
