package com.securous.backend.security.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtService {
    private final JwtProperties jwtProperties;
    private final SecretKey signingKey;
    public JwtService(JwtProperties jwtProperties){
        this.jwtProperties = jwtProperties;
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.secret());
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String email){
        long nowMs = System.currentTimeMillis();
        long expiry = nowMs + (jwtProperties.accessTokenLifeCycleSeconds()*1000L);
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date(nowMs))
                .setExpiration(new Date(expiry))
                .signWith(signingKey)
                .compact();
    }
}
