package com.securous.backend.exception;

import com.securous.backend.dto.ApiError;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    // 1. AUTHENTICATION FAILURES (login, JWT, disabled, locked)
    @ExceptionHandler({
            BadCredentialsException.class,
            UsernameNotFoundException.class,
            InsufficientAuthenticationException.class,
            io.jsonwebtoken.JwtException.class,
            DisabledException.class,
            LockedException.class
    })
    public ResponseEntity<ApiError> handleAuthErrors(Exception e,
                                                     HttpServletRequest request) {

        log.warn("AUTH ERROR [{}]: {}", e.getClass().getSimpleName(), e.getMessage());

        String message = switch (e.getClass().getSimpleName()) {
            case "JwtException" -> "Token is invalid or expired";
            case "InsufficientAuthenticationException" -> "Authentication is required";
            case "DisabledException" -> "Your account has been disabled";
            case "LockedException" -> "Your account is locked";
            default -> "Invalid email or password";
        };

        return build(HttpStatus.UNAUTHORIZED, "Unauthorized", message, request);
    }


    // 2. ACCESS DENIED (authorization failures)
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiError> handleAccessDenied(AccessDeniedException e,
                                                       HttpServletRequest request) {
        return build(HttpStatus.FORBIDDEN, "Forbidden",
                "You do not have permission", request);
    }


    // 3. RESOURCE NOT FOUND (DB + routing)
    @ExceptionHandler({
            ResourceNotFoundException.class,
            NoHandlerFoundException.class
    })
    public ResponseEntity<ApiError> handleNotFound(Exception e,
                                                   HttpServletRequest request) {

        String message = (e instanceof NoHandlerFoundException)
                ? "Route not found: " + request.getRequestURI()
                : e.getMessage();

        return build(HttpStatus.NOT_FOUND, "Not Found", message, request);
    }


    // 4. VALIDATION + BAD REQUEST ERRORS
    @ExceptionHandler({
            MethodArgumentNotValidException.class,
            ConstraintViolationException.class,
            HttpMessageNotReadableException.class,
            MissingServletRequestParameterException.class,
            MethodArgumentTypeMismatchException.class
    })
    public ResponseEntity<ApiError> handleBadRequest(Exception e,
                                                     HttpServletRequest request) {

        String message;

        if (e instanceof MethodArgumentNotValidException ex) {
            message = ex.getBindingResult().getFieldErrors().stream()
                    .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                    .collect(Collectors.joining(", "));
        }
        else if (e instanceof ConstraintViolationException ex) {
            message = ex.getConstraintViolations().stream()
                    .map(cv -> cv.getPropertyPath() + ": " + cv.getMessage())
                    .collect(Collectors.joining(", "));
        }
        else if (e instanceof MissingServletRequestParameterException ex) {
            message = "Missing parameter: " + ex.getParameterName();
        }
        else if (e instanceof MethodArgumentTypeMismatchException ex) {
            message = "Invalid value for parameter: " + ex.getName();
        }
        else if (e instanceof HttpMessageNotReadableException) {
            message = "Request body is missing or malformed";
        }
        else {
            message = "Bad request";
        }

        return build(HttpStatus.BAD_REQUEST, "Bad Request", message, request);
    }


    // 5. CONFLICT / DATA INTEGRITY
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiError> handleConflict(DataIntegrityViolationException e,
                                                   HttpServletRequest request) {

        String message = "A record with this value already exists";

        if (e.getMessage() != null && e.getMessage().contains("email")) {
            message = "An account with this email already exists";
        }

        return build(HttpStatus.CONFLICT, "Conflict", message, request);
    }


    // 6. GLOBAL FALLBACK (unexpected errors)
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleGeneral(Exception e,
                                                  HttpServletRequest request) {

        log.error("UNEXPECTED ERROR [{}]: {}", request.getRequestURI(), e.getMessage(), e);

        return build(HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "Something went wrong. Please try again later.",
                request);
    }


    // shared response builder
    private ResponseEntity<ApiError> build(HttpStatus status,
                                           String error,
                                           String message,
                                           HttpServletRequest request) {

        return ResponseEntity.status(status).body(
                ApiError.of(status.value(), error, message, request.getRequestURI())
        );
    }
}
