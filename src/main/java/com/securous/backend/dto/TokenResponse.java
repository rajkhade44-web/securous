package com.securous.backend.dto;

public record TokenResponse(
        String accessToken,
        String tokenType,
        UserDto user,
        long expiresIn
) {
    public static TokenResponse of(String accessToken,long expiresIn,UserDto user){
        return new TokenResponse(accessToken, "Bearer", user, expiresIn);
    }
}
