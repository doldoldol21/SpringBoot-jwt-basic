package com.auth.jwt.service;

import com.auth.jwt.exception.TokenRefreshException;
import com.auth.jwt.model.ERole;
import com.auth.jwt.model.RefreshToken;
import com.auth.jwt.model.Role;
import com.auth.jwt.model.User;
import com.auth.jwt.payload.request.LoginRequest;
import com.auth.jwt.payload.request.LogoutRequest;
import com.auth.jwt.payload.request.SignupRequest;
import com.auth.jwt.payload.request.TokenRefreshRequest;
import com.auth.jwt.payload.response.JwtResponse;
import com.auth.jwt.payload.response.MessageResponse;
import com.auth.jwt.payload.response.TokenRefreshResponse;
import com.auth.jwt.repository.RoleRepository;
import com.auth.jwt.repository.UserRepository;
import com.auth.jwt.security.jwt.JwtUtils;
import com.auth.jwt.security.service.UserDetailsImpl;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    public ResponseEntity<?> signin(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken((UserDetailsImpl) authentication.getPrincipal());

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails
            .getAuthorities()
            .stream()
            .map(item -> item.getAuthority())
            .collect(Collectors.toList());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());
        return ResponseEntity.ok(
            JwtResponse
                .builder()
                .accessToken(jwt)
                .refreshToken(refreshToken.getToken())
                .id(userDetails.getId())
                .username(userDetails.getUsername())
                .roles(roles)
                .build()
        );
    }

    public ResponseEntity<?> signup(SignupRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        Set<String> strRoles = request.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository
                .findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository
                            .findByName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    default:
                        Role userRole = roleRepository
                            .findByName(ERole.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                        break;
                }
            });
        }

        User user = User
            .builder()
            .username(request.getUsername())
            .password(passwordEncoder.encode(request.getPassword()))
            .roles(roles)
            .build();
        userRepository.save(user);
        log.info("user: {}", user);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    public ResponseEntity<?> refreshtoken(TokenRefreshRequest request) {
        String refreshToken = request.getRefreshToken();

        return refreshTokenService
            .findByToken(refreshToken)
            .map(refreshTokenService::verifyExpiration)
            .map(RefreshToken::getUser)
            .map(user -> {
                String token = jwtUtils.generateTokenFromUsername(user.getUsername());
                return ResponseEntity.ok(
                    TokenRefreshResponse.builder().accessToken(token).refreshToken(refreshToken).build()
                );
            })
            .orElseThrow(() -> new TokenRefreshException(refreshToken, "Refresh token is not in database!"));
    }

    public ResponseEntity<?> logout(LogoutRequest request) {
        refreshTokenService.deleteByUserId(request.getUserId());
        return ResponseEntity.ok(new MessageResponse("Log out successful!"));
    }
}
