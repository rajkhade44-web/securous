package com.securous.backend.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest (
    @Email(message = "Must be a valid email")
    @NotBlank(message = "Email is required")
    String email,

    @NotBlank(message = "Password is required")
    String password
    ){
}
