package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.Key;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/* --------------------------------------------------------------------
 * 🔐 SECURITY CONFIGURATION
 * --------------------------------------------------------------------
 * PART 1: Password hashing (BCrypt)
 * PART 2: Access Control
 * PART 3: JWT Validation (iss, aud, isAdmin, expiration)
 * PART 6: Mass Assignment Prevention
 * PART 7: JWT Hardening (secure key, TTL, issuer, audience)
 * -------------------------------------------------------------------- */
@Configuration
public class SecurityConfig {

    // Secret key loaded securely from environment or config
    @Value("${app.jwt.secret}")
    private String secret;

    // Expected issuer & audience (configured in application.properties)
    private static final String EXPECTED_ISSUER = "owasp-api-lab";
    private static final String EXPECTED_AUDIENCE = "owasp-api-users";

    /* ---------------------------------------------------------------
     * 🧩 PART 1: PASSWORD SECURITY
     * --------------------------------------------------------------- */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /* ---------------------------------------------------------------
     * 🧱 PART 2 & 6: ACCESS CONTROL + MASS ASSIGNMENT PREVENTION
     * --------------------------------------------------------------- */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // Public endpoints: authentication and signup (POST /api/users) and test error route
                .requestMatchers("/api/auth/**", "/api/users/test/error").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/users").permitAll()
                .requestMatchers("/h2-console/**").permitAll()
                // Role-based endpoints
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/users/**", "/api/accounts/**").authenticated()
                // Everything else requires authentication
                .anyRequest().authenticated()
            )
            .exceptionHandling(ex -> ex
                // PART 7: JWT Hardening — Clearer, consistent error messages
                .authenticationEntryPoint((req, res, excep) ->
                        res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: Invalid or expired token"))
                .accessDeniedHandler((req, res, excep) ->
                        res.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden: Access denied"))
            )
            // PART 7: Add JWT validation filter
            .addFilterBefore(new JwtFilter(secret), UsernamePasswordAuthenticationFilter.class);

        // Allow H2 console frames for testing (safe only in dev)
        http.headers(h -> h.frameOptions(f -> f.disable()));

        return http.build();
    }

    /* ---------------------------------------------------------------
     * 🛡️ PART 3 & 7: JWT FILTER — Validation + Hardening
     * --------------------------------------------------------------- */
    static class JwtFilter extends OncePerRequestFilter {
        private final Key signingKey;

        JwtFilter(String secret) {
            // PART 7: Use strong key with HS256
            this.signingKey = new SecretKeySpec(secret.getBytes(), SignatureAlgorithm.HS256.getJcaName());
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain chain)
                throws ServletException, IOException {

            String auth = request.getHeader("Authorization");

            try {
                if (auth != null && auth.startsWith("Bearer ")) {
                    String token = auth.substring(7);

                    // ✅ PART 7: Strict JWT parsing with issuer/audience validation
                    Claims c = Jwts.parserBuilder()
                            .setSigningKey(signingKey)
                            .requireIssuer(EXPECTED_ISSUER)
                            .requireAudience(EXPECTED_AUDIENCE)
                            .build()
                            .parseClaimsJws(token)
                            .getBody();

                    // ✅ Validate expiration explicitly
                    if (c.getExpiration() == null || c.getExpiration().before(new Date())) {
                        throw new JwtException("Token expired");
                    }

                    // ✅ Extract claims safely
                    String user = c.getSubject();
                    String role = (String) c.get("role");
                    Boolean isAdmin = (Boolean) c.get("isAdmin");

                    // ✅ Assign authorities
                    List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    if (role != null) authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                    if (Boolean.TRUE.equals(isAdmin)) authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));

                    // ✅ Authenticate user in Spring Security context
                    if (user != null) {
                        UsernamePasswordAuthenticationToken authn =
                                new UsernamePasswordAuthenticationToken(user, null, authorities);
                        SecurityContextHolder.getContext().setAuthentication(authn);
                    }
                }
            } catch (JwtException | IllegalArgumentException e) {
                // PART 7: Hardened response — no stacktrace exposure
                SecurityContextHolder.clearContext();
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired token");
                return;
            }

            chain.doFilter(request, response);
        }
    }
}
