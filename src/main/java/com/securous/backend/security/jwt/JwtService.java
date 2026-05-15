package com.securous.backend.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtService {
    private JwtProperties jwtProperties;
    private SecretKey signingKey;

    public JwtService(JwtProperties jwtProperties){
        this.jwtProperties = jwtProperties;
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.secret());
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String email){
        long nowMs = System.currentTimeMillis();
        long expiryMs = nowMs + (jwtProperties.accessTokenLifeCycleSeconds()*1000L);
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date(nowMs))
                .setExpiration(new Date(expiryMs))
                .signWith(signingKey)
                .compact();
    }

    public Claims parseToken(String token){
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenExpired(String token){
        try{
            parseToken(token);
            return false;
        }catch (ExpiredJwtException e){
            return  true;
        }catch (JwtException e){
            return false;
        }
    }

    public String getEmailFromToken(String token){
        Claims claims = parseToken(token);
        return claims.getSubject();
    }

    public String generateTokenWithExpiration(String email, long expiry){
        long nowMs = System.currentTimeMillis();
        long expMs = nowMs + (expiry*1000L);
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date(nowMs))
                .setExpiration(new Date(expMs))
                .signWith(signingKey)
                .compact();
    }
}
