package com.gasagency.controller;

import com.gasagency.entity.User;
import com.gasagency.entity.BusinessInfo;
import com.gasagency.entity.RefreshToken;
import com.gasagency.repository.UserRepository;
import com.gasagency.repository.BusinessInfoRepository;
import com.gasagency.repository.RefreshTokenRepository;
import com.gasagency.util.JwtUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private BusinessInfoRepository businessInfoRepository;

    // ===========================
    // LOGIN
    // ===========================
    @PostMapping("/login")
    public Map<String, Object> login(
            @RequestBody Map<String, String> loginRequest,
            HttpServletResponse response) {

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.get("username"),
                            loginRequest.get("password")
                    )
            );

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // Access token (15 min)
            String accessToken = jwtUtil.generateToken(userDetails, 15 * 60 * 1000L);

            // Refresh token (7 days)
            String refreshTokenStr = UUID.randomUUID().toString();
            Instant expiry = Instant.now().plusSeconds(7 * 24 * 60 * 60);

            RefreshToken refreshToken = new RefreshToken();
            refreshToken.setToken(refreshTokenStr);
            refreshToken.setUsername(userDetails.getUsername());
            refreshToken.setExpiryDate(expiry);
            refreshTokenRepository.save(refreshToken);

            // ===== ACCESS TOKEN COOKIE =====
            ResponseCookie accessCookie = ResponseCookie.from("jwt_token", accessToken)
                    .httpOnly(true)
                    .secure(true)
                    .sameSite("None")
                    .path("/")
                    .maxAge(Duration.ofMinutes(15))
                    .build();

            // ===== REFRESH TOKEN COOKIE =====
            ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", refreshTokenStr)
                    .httpOnly(true)
                    .secure(true)
                    .sameSite("None")
                    .path("/")
                    .maxAge(Duration.ofDays(7))
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
            response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

            User user = userRepository.findByUsername(userDetails.getUsername())
                    .orElseThrow();

            Map<String, Object> resp = new HashMap<>();
            resp.put("id", user.getId());
            resp.put("role", user.getRole());
            resp.put("name", user.getName());
            resp.put("username", user.getUsername());
            resp.put("mobileNo", user.getMobileNo());
            resp.put("businessId",
                    user.getBusiness() != null ? user.getBusiness().getId() : null
            );

            return resp;

        } catch (BadCredentialsException e) {
            throw new RuntimeException("Invalid username or password");
        }
    }

    // ===========================
    // REFRESH TOKEN
    // ===========================
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) {

        String refreshTokenStr = null;

        if (request.getCookies() != null) {
            for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
                if ("refresh_token".equals(cookie.getName())) {
                    refreshTokenStr = cookie.getValue();
                }
            }
        }

        if (refreshTokenStr == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("No refresh token");
        }

        RefreshToken refreshToken = refreshTokenRepository
                .findByToken(refreshTokenStr)
                .orElse(null);

        if (refreshToken == null || refreshToken.getExpiryDate().isBefore(Instant.now())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid or expired refresh token");
        }

        UserDetails userDetails = userRepository
                .findByUsername(refreshToken.getUsername())
                .map(u -> new org.springframework.security.core.userdetails.User(
                        u.getUsername(),
                        u.getPassword(),
                        Collections.singleton(
                                new org.springframework.security.core.authority
                                        .SimpleGrantedAuthority("ROLE_" + u.getRole().name())
                        )
                ))
                .orElse(null);

        if (userDetails == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("User not found");
        }

        String newAccessToken = jwtUtil.generateToken(userDetails, 15 * 60 * 1000L);

        ResponseCookie accessCookie = ResponseCookie.from("jwt_token", newAccessToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .path("/")
                .maxAge(Duration.ofMinutes(15))
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());

        return ResponseEntity.ok("Access token refreshed");
    }

    // ===========================
    // LOGOUT
    // ===========================
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            HttpServletRequest request,
            HttpServletResponse response) {

        ResponseCookie deleteAccess = ResponseCookie.from("jwt_token", "")
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .path("/")
                .maxAge(0)
                .build();

        ResponseCookie deleteRefresh = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .path("/")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, deleteAccess.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, deleteRefresh.toString());

        if (request.getCookies() != null) {
            for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
                if ("refresh_token".equals(cookie.getName())) {
                    refreshTokenRepository.deleteByToken(cookie.getValue());
                }
            }
        }

        return ResponseEntity.ok("Logged out successfully");
    }

    // ===========================
    // REGISTER
    // ===========================
    @PostMapping("/register")
    public User register(@RequestBody Map<String, String> registerRequest) {

        if (!registerRequest.containsKey("businessId")) {
            throw new RuntimeException("businessId is required");
        }

        Long businessId = Long.parseLong(registerRequest.get("businessId"));

        BusinessInfo business = businessInfoRepository.findById(businessId)
                .orElseThrow(() -> new RuntimeException("Business not found"));

        User user = new User();
        user.setUsername(registerRequest.get("username"));
        user.setPassword(passwordEncoder.encode(registerRequest.get("password")));
        user.setRole(User.Role.valueOf(registerRequest.get("role")));
        user.setName(registerRequest.getOrDefault("name", ""));
        user.setMobileNo(registerRequest.getOrDefault("mobileNo", ""));
        user.setActive(true);
        user.setBusiness(business);

        return userRepository.save(user);
    }
}
