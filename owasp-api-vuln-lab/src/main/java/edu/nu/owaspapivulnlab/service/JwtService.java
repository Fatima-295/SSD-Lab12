package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

/* ------------------------------------------------------------
 * 🛡️ PART 7: JWT HARDENING
 * ------------------------------------------------------------
 * ✅ Uses a strong HMAC key from environment variables
 * ✅ Adds issuer and audience claims
 * ✅ Sets short token lifetime (TTL)
 * ✅ Strict signature algorithm (HS256)
 * ------------------------------------------------------------ */
@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.ttl-seconds}")
    private long ttlSeconds;

    // Hardcoded constants (must match SecurityConfig validation)
    private static final String ISSUER = "owasp-api-lab";
    private static final String AUDIENCE = "owasp-api-users";

    public String issue(String subject, Map<String, Object> claims) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date exp = new Date(nowMillis + ttlSeconds * 1000);

        // ✅ Secure key generation using secret
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

    // Build token with issuer/audience so tokens issued by login are accepted by JwtFilter
    return Jwts.builder()
        .setClaims(claims)
        .setSubject(subject)
        .setIssuedAt(now)
        .setExpiration(exp)
        .setIssuer(ISSUER)
        .setAudience(AUDIENCE)
        .signWith(key, SignatureAlgorithm.HS256)
        .compact();
    }
}
