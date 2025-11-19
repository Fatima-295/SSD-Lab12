package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*; // ✅ Added for Part 9
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // =====================================================
    // Part 3 + 4: Ownership & Data Exposure Control
    // =====================================================
    @GetMapping("/{id}/balance")
    public Map<String, Object> balance(@PathVariable("id") Long id, Authentication authentication) {
        AppUser currentUser = users.findByUsername(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        Account account = accounts.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Account not found"));

        if (!currentUser.isAdmin() && !account.getOwnerUserId().equals(currentUser.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
        }

        Map<String, Object> res = new HashMap<>();
        res.put("accountId", account.getId());
        res.put("balance", account.getBalance());
        res.put("ownerId", account.getOwnerUserId());
        return res;
    }

    // =====================================================
    // Part 3 + 4 + 6 + 9:
    // Ownership Enforcement + Mass Assignment Prevention + Input Validation
    // =====================================================
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(
            @PathVariable("id") Long id,
            @RequestParam("amount")
            @NotNull(message = "Amount is required")
            @DecimalMin(value = "0.01", message = "Amount must be positive")
            @DecimalMax(value = "1000000.00", message = "Amount too large") Double amount,
            Authentication authentication) {

        AppUser currentUser = users.findByUsername(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        Account account = accounts.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Account not found"));

        if (!currentUser.isAdmin() && !account.getOwnerUserId().equals(currentUser.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
        }

        // ✅ Validation logic for insufficient funds
        if (amount > account.getBalance()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Insufficient balance");
        }

        account.setBalance(account.getBalance() - amount);
        accounts.save(account);

        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("accountId", account.getId());
        response.put("remaining", account.getBalance());
        return ResponseEntity.ok(response);
    }

    // =====================================================
    // Part 3 + 4: Authenticated user's accounts
    // =====================================================
    @GetMapping("/mine")
    public List<Map<String, Object>> mine(Authentication authentication) {
        AppUser currentUser = users.findByUsername(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        return accounts.findByOwnerUserId(currentUser.getId()).stream().map(a -> {
            Map<String, Object> res = new HashMap<>();
            res.put("accountId", a.getId());
            res.put("balance", a.getBalance());
            return res;
        }).collect(Collectors.toList());
    }

    // =====================================================
    // Part 3 + 4: Admin-only account view
    // =====================================================
    @GetMapping("/{id}/admin")
    public Map<String, Object> viewAny(@PathVariable Long id, Authentication authentication) {
        AppUser currentUser = users.findByUsername(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        if (!currentUser.isAdmin()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
        }

        Account account = accounts.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Account not found"));

        Map<String, Object> res = new HashMap<>();
        res.put("accountId", account.getId());
        res.put("balance", account.getBalance());
        res.put("ownerId", account.getOwnerUserId());
        return res;
    }
}
