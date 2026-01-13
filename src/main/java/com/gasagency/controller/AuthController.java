package com.gasagency.controller;
import com.gasagency.entity.*;
import com.gasagency.repository.*;
import com.gasagency.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

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

    /* ================= COOKIE HELPER (IMPORTANT) ================= */
    private void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        String cookie = String.format(
                "%s=%s; Max-Age=%d; Path=/; Secure; HttpOnly; SameSite=None",
                name,
                value,
                maxAge
        );
        response.addHeader("Set-Cookie", cookie);
    }

    /* ================= LOGIN ================= */
    @PostMapping("/login")
    public Map<String, Object> login(
            @RequestBody Map<String, String> loginRequest,
            HttpServletResponse response
    ) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.get("username"),
                        loginRequest.get("password")
                )
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        // Access Token (15 min)
        String accessToken = jwtUtil.generateToken(userDetails, 15 * 60 * 1000L);

        // Refresh Token (7 days)
        String refreshTokenStr = UUID.randomUUID().toString();
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(refreshTokenStr);
        refreshToken.setUsername(userDetails.getUsername());
        refreshToken.setExpiryDate(Instant.now().plusSeconds(7 * 24 * 60 * 60));
        refreshTokenRepository.save(refreshToken);

        // Cookies
        addCookie(response, "jwt_token", accessToken, 15 * 60);
        addCookie(response, "refresh_token", refreshTokenStr, 7 * 24 * 60 * 60);

        User user = userRepository.findByUsername(userDetails.getUsername()).orElseThrow();

        Map<String, Object> resp = new HashMap<>();
        resp.put("id", user.getId());
        resp.put("role", user.getRole());
        resp.put("name", user.getName());
        resp.put("username", user.getUsername());
        resp.put("mobileNo", user.getMobileNo());
        resp.put("businessId", user.getBusiness() != null ? user.getBusiness().getId() : null);

        return resp;
    }

    /* ================= REFRESH TOKEN ================= */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        String refreshTokenStr = null;
        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if ("refresh_token".equals(cookie.getName())) {
                    refreshTokenStr = cookie.getValue();
                }
            }
        }

        if (refreshTokenStr == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No refresh token");
        }

        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenStr).orElse(null);
        if (refreshToken == null || refreshToken.getExpiryDate().isBefore(Instant.now())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired refresh token");
        }

        User user = userRepository.findByUsername(refreshToken.getUsername()).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found");
        }

        UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
        );

        String newAccessToken = jwtUtil.generateToken(userDetails, 15 * 60 * 1000L);
        addCookie(response, "jwt_token", newAccessToken, 15 * 60);

        return ResponseEntity.ok("Access token refreshed");
    }

    /* ================= LOGOUT ================= */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        addCookie(response, "jwt_token", "", 0);
        addCookie(response, "refresh_token", "", 0);

        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if ("refresh_token".equals(cookie.getName())) {
                    refreshTokenRepository.deleteByToken(cookie.getValue());
                }
            }
        }

        return ResponseEntity.ok("Logged out");
    }

    /* ================= REGISTER ================= */
    @PostMapping("/register")
    public User register(@RequestBody Map<String, String> registerRequest) {

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
