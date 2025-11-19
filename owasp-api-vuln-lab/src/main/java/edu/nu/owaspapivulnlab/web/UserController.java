package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*; // ✅ For input validation
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;

    public UserController(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    // =====================================================
    // Part 3 & 4: Ownership Enforcement / Data Exposure
    // =====================================================
    @GetMapping("/me")
    public Map<String, Object> getMe(Authentication authentication) {
        if (authentication == null) {
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED, "Access denied");
        }

        AppUser user = users.findByUsername(authentication.getName())
                .orElseThrow(() -> new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.NOT_FOUND, "User not found"));

        Map<String, Object> res = new HashMap<>();
        res.put("id", user.getId());
        res.put("username", user.getUsername());
        res.put("email", user.getEmail());
        return res;
    }

    // =====================================================
    // Part 3 & 4: Get user by ID (Ownership check)
    // =====================================================
    @GetMapping("/{id}")
    public Map<String, Object> get(@PathVariable("id") Long id, Authentication authentication) {
        AppUser currentUser = users.findByUsername(authentication.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        AppUser targetUser = users.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!currentUser.isAdmin() && !currentUser.getId().equals(id)) {
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.FORBIDDEN, "Access denied");
        }

        Map<String, Object> res = new HashMap<>();
        res.put("id", targetUser.getId());
        res.put("username", targetUser.getUsername());
        res.put("email", targetUser.getEmail());
        return res;
    }

    // =====================================================
    // Part 1 + 6 + 9: Secure User Creation
    // (Password Hashing, Mass Assignment, Input Validation)
    // =====================================================
    @PostMapping
    public ResponseEntity<Map<String, Object>> createUser(
        @Valid @RequestBody CreateUserRequest request // ✅ replaced Map<> with DTO
    ) {
        if (users.findByUsername(request.getUsername()).isPresent()) {
            throw new RuntimeException("Username already exists");
        }

        AppUser newUser = new AppUser();
        newUser.setUsername(request.getUsername());
        newUser.setPassword(passwordEncoder.encode(request.getPassword())); // ✅ Secure hashing
        newUser.setRole("USER");
        newUser.setAdmin(false);
        newUser.setEmail(request.getEmail());

        AppUser saved = users.save(newUser);

        Map<String, Object> res = new HashMap<>();
        res.put("id", saved.getId());
        res.put("username", saved.getUsername());
        res.put("email", saved.getEmail());
    // Do not reflect client-controlled role/isAdmin values; return server-assigned values
        res.put("role", saved.getRole());
        res.put("isAdmin", saved.isAdmin());
        return ResponseEntity.status(201).body(res);
    }

    // =====================================================
    // Part 9: Validated Search Endpoint
    // =====================================================
    @GetMapping("/search")
    public List<Map<String, Object>> searchUsers(
            @RequestParam
            @NotBlank(message = "Query must not be blank")
            @Size(max = 30, message = "Search query too long") String q,

            @RequestParam(defaultValue = "10")
            @Min(value = 1, message = "Limit must be at least 1")
            @Max(value = 100, message = "Limit cannot exceed 100") int limit,

            Authentication authentication) {

        AppUser currentUser = users.findByUsername(authentication.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!currentUser.isAdmin()) {
            throw new RuntimeException("Access denied");
        }

        return users.search(q).stream().limit(limit).map(u -> {
            Map<String, Object> res = new HashMap<>();
            res.put("id", u.getId());
            res.put("username", u.getUsername());
            res.put("email", u.getEmail());
            return res;
        }).collect(Collectors.toList());
    }

    // =====================================================
    // Admin-only: List and Delete Users
    // =====================================================
    @GetMapping
    public List<Map<String, Object>> listUsers(Authentication authentication) {
        if (authentication == null) {
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED, "Access denied");
        }

        AppUser currentUser = users.findByUsername(authentication.getName())
                .orElseThrow(() -> new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.NOT_FOUND, "User not found"));

        if (!currentUser.isAdmin()) {
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.FORBIDDEN, "Access denied");
        }

        return users.findAll().stream().map(u -> {
            Map<String, Object> res = new HashMap<>();
            res.put("id", u.getId());
            res.put("username", u.getUsername());
            res.put("email", u.getEmail());
            return res;
        }).collect(Collectors.toList());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, String>> deleteUser(@PathVariable Long id, Authentication authentication) {
        AppUser currentUser = users.findByUsername(authentication.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!currentUser.isAdmin()) {
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.FORBIDDEN, "Access denied");
        }

        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }

    // ==========================
    // DTO for Part 9: Input Validation
    // ==========================
    public static class CreateUserRequest {

        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 30, message = "Username must be between 3 and 30 characters")
        @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username may only contain letters, numbers, and underscores")
        private String username;

    @NotBlank(message = "Password is required")
    @Size(min = 2, max = 64, message = "Password must be between 2 and 64 characters")
        private String password;

        @Email(message = "Invalid email format")
        @Size(max = 100, message = "Email too long")
        private String email;

        // getters and setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }

        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }

        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }


    // =====================================================
    // Part 8: Error Handling & Logging (for testing)
    // =====================================================
    @GetMapping("/test/error")
    public ResponseEntity<?> triggerError() {
        throw new RuntimeException("Simulated server error for Part 8 testing");
    }
}
