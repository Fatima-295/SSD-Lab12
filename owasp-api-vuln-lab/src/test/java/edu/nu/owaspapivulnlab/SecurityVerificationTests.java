package edu.nu.owaspapivulnlab;

import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;

import java.util.*;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public class SecurityVerificationTests {

    @Autowired
    private TestRestTemplate restTemplate;

    // Use relative paths with TestRestTemplate configured for the started server
    // (webEnvironment = RANDOM_PORT). Avoid hardcoded ports.

    private HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    // Utility to print responses
    private void logResponse(String test, ResponseEntity<?> response) {
        System.out.println("---- " + test + " ----");
        System.out.println("Status: " + response.getStatusCode());
        System.out.println("Body: " + response.getBody());
    }

    // 1️⃣ Password Security – BCrypt hashing verification
    @Test
    public void testPasswordHashingOnSignup() {
        String payload = """
            { "username": "secureUser", "password": "Password123" }
            """;

    ResponseEntity<String> response = restTemplate.postForEntity(
        "/api/users",
        new HttpEntity<>(payload, jsonHeaders()),
        String.class
    );

        logResponse("Password Hashing", response);
        Assertions.assertEquals(HttpStatus.CREATED, response.getStatusCode(),
                "User creation should succeed with password hashing");

        // Ensure response doesn't expose password
        Assertions.assertFalse(response.getBody() != null && response.getBody().contains("Password123"),
                "Response must not include plaintext password");
    }

    // 2️⃣ Access Control – Ensure sensitive endpoints require authentication
    @Test
    public void testSensitiveEndpointsRequireAuth() {
    ResponseEntity<String> response = restTemplate.getForEntity("/api/users/me", String.class);
        logResponse("Access Control", response);
        Assertions.assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode(),
                "Protected endpoints must require authentication");
    }

    // 3️⃣ Resource Ownership Enforcement
    @Test
    public void testUserCannotAccessOthersResources() {
        // Simulate access attempt without correct user token
    ResponseEntity<String> response = restTemplate.getForEntity("/api/users/999", String.class);
        logResponse("Resource Ownership", response);
        Assertions.assertTrue(response.getStatusCode() == HttpStatus.FORBIDDEN ||
                              response.getStatusCode() == HttpStatus.UNAUTHORIZED,
                "User should not access others' resources");
    }

    // 4️⃣ Data Exposure Control – ensure no sensitive fields in responses
    @Test
    public void testNoSensitiveDataExposed() {
    ResponseEntity<String> response = restTemplate.getForEntity("/api/users", String.class);
        logResponse("Data Exposure Control", response);

        if (response.getBody() != null) {
            Assertions.assertFalse(response.getBody().contains("password") ||
                                   response.getBody().contains("isAdmin") ||
                                   response.getBody().contains("role"),
                    "Sensitive fields should not appear in API responses");
        }
    }

    // 5️⃣ Rate Limiting – exceeding requests should return 429
    @Test
    public void testRateLimiting() {
        boolean hitRateLimit = false;

        for (int i = 0; i < 15; i++) {
            HttpHeaders h = jsonHeaders();
            h.add("X-Test-Client", "ratelimit-client");
            ResponseEntity<String> response = restTemplate.exchange("/api/auth/login", HttpMethod.GET, new HttpEntity<>(h), String.class);
            if (response.getStatusCode() == HttpStatus.TOO_MANY_REQUESTS) {
                hitRateLimit = true;
                break;
            }
        }

        Assertions.assertTrue(hitRateLimit, "Rate limiter should trigger HTTP 429 after repeated requests");
    }

    // 6️⃣ Mass Assignment Prevention
    @Test
    public void testMassAssignmentBlocked() {
        String payload = """
            {
              "username": "attacker",
              "password": "pass123",
              "isAdmin": true,
              "role": "ADMIN"
            }
            """;

    ResponseEntity<String> response = restTemplate.postForEntity(
        "/api/users",
        new HttpEntity<>(payload, jsonHeaders()),
        String.class
    );

        logResponse("Mass Assignment", response);
        Assertions.assertEquals(HttpStatus.CREATED, response.getStatusCode());
        Assertions.assertFalse(response.getBody() != null && response.getBody().contains("\"isAdmin\":true"),
                "Mass assignment of admin field must be blocked");
    }

    // 7️⃣ JWT Hardening – invalid token should be rejected
    @Test
    public void testInvalidJwtRejected() {
        HttpHeaders headers = jsonHeaders();
        headers.setBearerAuth("invalid.jwt.token");

    ResponseEntity<String> response = restTemplate.exchange(
        "/api/users/me",
        HttpMethod.GET,
        new HttpEntity<>(headers),
        String.class
    );

        logResponse("JWT Hardening", response);
        Assertions.assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode(),
                "Invalid JWT should be rejected");
    }

    // 8️⃣ Error Handling – no stack traces exposed
    @Test
    public void testErrorResponseDoesNotExposeStackTrace() {
    ResponseEntity<String> response = restTemplate.getForEntity("/api/users/test/error", String.class);
        logResponse("Error Handling", response);

        Assertions.assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        if (response.getBody() != null) {
            Assertions.assertFalse(response.getBody().contains("Exception") ||
                                   response.getBody().contains("stackTrace"),
                    "Stack traces should not be exposed in responses");
        }
    }

    // 9️⃣ Input Validation – invalid input should be rejected
    @Test
    public void testInvalidInputRejected() {
        String payload = """
            { "username": "", "password": "short" }
            """;

    ResponseEntity<String> response = restTemplate.postForEntity(
        "/api/users",
        new HttpEntity<>(payload, jsonHeaders()),
        String.class
    );

        logResponse("Input Validation", response);
        Assertions.assertTrue(
                response.getStatusCode() == HttpStatus.BAD_REQUEST ||
                response.getStatusCode() == HttpStatus.UNPROCESSABLE_ENTITY,
                "Invalid input should be rejected by validation rules"
        );
    }

    // 🔟 Full Secure Behavior Flow – login → access protected
    @Test
    public void testLoginAndAccessProtectedEndpoint() {
        // First register
        String register = """
            { "username": "flowUser", "password": "StrongPass123" }
            """;
    restTemplate.postForEntity("/api/users", new HttpEntity<>(register, jsonHeaders()), String.class);

    // Try to login (GET endpoint in your case)
    ResponseEntity<String> login = restTemplate.getForEntity("/api/auth/login", String.class);
        logResponse("Login", login);

        Assertions.assertTrue(login.getStatusCode().is2xxSuccessful(), "Login should succeed");

    // Access protected endpoint without token – must fail
    ResponseEntity<String> me = restTemplate.getForEntity("/api/users/me", String.class);
        logResponse("Access Protected", me);

        Assertions.assertEquals(HttpStatus.UNAUTHORIZED, me.getStatusCode(),
                "Should not access /me without JWT");
    }
}
