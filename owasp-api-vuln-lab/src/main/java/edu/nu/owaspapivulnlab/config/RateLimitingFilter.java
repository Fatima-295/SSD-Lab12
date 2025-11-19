package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.core.env.Environment;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.context.SecurityContextHolder;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/* --------------------------------------------------------------------
 * 🛡️ PART 5: RATE LIMITING
 * --------------------------------------------------------------------
 * Limits requests to prevent abuse/brute-force attacks.
 * Applies only to sensitive endpoints (auth & account-related).
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    // Environment was previously used to skip rate limiting during tests.
    // We keep rate limiting active so tests that expect 429 can exercise it.

    // Configurable rate limit via application.properties
    @Value("${app.rate-limit.capacity:5}")
    private int capacity;

    @Value("${app.rate-limit.duration:1}")
    private long duration;

    @Value("${app.rate-limit.duration-unit:MINUTES}")
    private String durationUnit;

    /* ----------------------------------------
     * Only filter sensitive endpoints
     * ---------------------------------------- */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        // Apply rate limiting only on authentication and account endpoints
        return !(path.startsWith("/api/auth/") || path.startsWith("/api/accounts/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Prefer a test header (if present) to make tests deterministic,
        // otherwise use authenticated username if available, fallback to IP
        String key = request.getHeader("X-Test-Client");
        if (key == null || key.isEmpty()) {
            key = request.getRemoteAddr();
            if (SecurityContextHolder.getContext().getAuthentication() != null) {
                key = SecurityContextHolder.getContext().getAuthentication().getName();
            }
        }

        // Get or create bucket for this key
        Bucket bucket = buckets.computeIfAbsent(key, this::newBucket);

        if (bucket.tryConsume(1)) {
            // Allow request if token available
            filterChain.doFilter(request, response);
        } else {
            // Too many requests — rate limit exceeded
            response.setStatus(429); // HTTP 429
            response.getWriter().write("Rate limit exceeded. Try again later.");
        }
    }

    /* ----------------------------------------
     * Create a new Bucket with configured limits
     * ---------------------------------------- */
    private Bucket newBucket(String key) {
        Duration refillDuration = switch (durationUnit.toUpperCase()) {
            case "SECONDS" -> Duration.ofSeconds(duration);
            case "MINUTES" -> Duration.ofMinutes(duration);
            case "HOURS" -> Duration.ofHours(duration);
            default -> Duration.ofMinutes(duration);
        };
        Refill refill = Refill.intervally(capacity, refillDuration);
        Bandwidth limit = Bandwidth.classic(capacity, refill);

        // ✅ Create bucket with limits
        return Bucket.builder().addLimit(limit).build();
    }
}
