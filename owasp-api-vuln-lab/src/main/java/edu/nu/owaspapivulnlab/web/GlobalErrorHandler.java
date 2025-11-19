package edu.nu.owaspapivulnlab.web;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;

/* --------------------------------------------------------------------
 * 🧱 PART 8 & 9: CENTRALIZED ERROR HANDLING & LOGGING
 * --------------------------------------------------------------------
 * - Prevents stack traces from leaking to clients
 * - Logs errors securely on the server side
 * - Handles validation errors, status exceptions, and generic issues
 * -------------------------------------------------------------------- */
@ControllerAdvice
public class GlobalErrorHandler {

    /* ----------------------------------------------------------------
     * 🔹 Handles input validation errors (e.g., @Valid, @NotBlank, etc.)
     * ---------------------------------------------------------------- */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationError(MethodArgumentNotValidException ex) {

        System.err.println("Validation Error: " + ex.getMessage());

        Map<String, Object> errorBody = new HashMap<>();
        errorBody.put("status", HttpStatus.BAD_REQUEST.value());
        errorBody.put("error", "Bad Request");

        String message = ex.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(err -> err.getDefaultMessage())
                .orElse("Invalid input data");
        errorBody.put("message", message);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorBody);
    }

    /* ----------------------------------------------------------------
     * 🔹 Handles explicit status-based exceptions (e.g., 400, 403, 404)
     * ---------------------------------------------------------------- */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, Object>> handleResponseStatus(ResponseStatusException ex) {

        System.err.println("ResponseStatusException: " + ex.getReason());

        Map<String, Object> errorBody = new HashMap<>();
        HttpStatusCode statusCode = ex.getStatusCode();

        // ✅ Safely get the reason phrase (compatible with Spring Boot 3)
        String reasonPhrase = (statusCode instanceof HttpStatus)
                ? ((HttpStatus) statusCode).getReasonPhrase()
                : "Error";

        errorBody.put("status", statusCode.value());
        errorBody.put("error", reasonPhrase);
        errorBody.put("message", ex.getReason());

        return ResponseEntity.status(statusCode).body(errorBody);
    }

    /* ----------------------------------------------------------------
     * 🔹 Handles database-related exceptions
     * ---------------------------------------------------------------- */
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<Map<String, Object>> handleDatabaseError(DataAccessException ex) {

        System.err.println("Database Error: " + ex.getMessage());

        Map<String, Object> errorBody = new HashMap<>();
        errorBody.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        errorBody.put("error", "Database Error");
        errorBody.put("message", "A database operation failed. Please try again later.");

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorBody);
    }

    /* ----------------------------------------------------------------
     * 🔹 Fallback for all unexpected / uncaught exceptions
     * ---------------------------------------------------------------- */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) {

        ex.printStackTrace();

        Map<String, Object> errorBody = new HashMap<>();
        errorBody.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        errorBody.put("error", "Internal Server Error");
        errorBody.put("message", "An unexpected error occurred. Please contact support.");

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorBody);
    }
}
