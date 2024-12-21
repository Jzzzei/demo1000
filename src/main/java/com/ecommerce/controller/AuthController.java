package com.ecommerce.controller;

import com.ecommerce.dto.LoginRequest;
import com.ecommerce.dto.RegisterRequest;
import com.ecommerce.model.User;
import com.ecommerce.security.JwtTokenProvider;
import com.ecommerce.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Authentication management APIs")
public class AuthController {
    @Autowired
    private UserService userService;
    
    @Autowired
    private JwtTokenProvider tokenProvider;
    
    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Operation(summary = "Register a new user")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User registered successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid input data")
    })
@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest) {
    User user = userService.registerUser(registerRequest);
    
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            registerRequest.getUsername(),
            registerRequest.getPassword()
        )
    );

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = tokenProvider.generateToken((UserDetails)authentication.getPrincipal());

    Map<String, Object> response = new HashMap<>();
    response.put("token", jwt);
    response.put("user", user);
    
    return ResponseEntity.ok(response);
}
    
    @Operation(summary = "Login user")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Login successful"),
        @ApiResponse(responseCode = "401", description = "Invalid credentials")
    })
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(),
                loginRequest.getPassword()
            )
        );
        
        String token = tokenProvider.generateToken(loginRequest.getUsername());
        
        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("user", userService.findByUsername(loginRequest.getUsername()));
        
        return ResponseEntity.ok(response);
    }
} 