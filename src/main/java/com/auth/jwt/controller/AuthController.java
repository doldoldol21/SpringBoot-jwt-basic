package com.auth.jwt.controller;

import com.auth.jwt.payload.request.LoginRequest;
import com.auth.jwt.payload.request.LogoutRequest;
import com.auth.jwt.payload.request.SignupRequest;
import com.auth.jwt.payload.request.TokenRefreshRequest;
import com.auth.jwt.service.AuthService;
import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest request) {
        return authService.signin(request);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest request) {
        return authService.signup(request);
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody TokenRefreshRequest request) {
        return authService.refreshtoken(request);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@Valid @RequestBody LogoutRequest request) {
        return authService.logout(request);
    }
}
