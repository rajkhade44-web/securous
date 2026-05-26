package com.securous.backend.security.jwt;

import com.securous.backend.entity.Role;
import com.securous.backend.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;

@Component
public class JwtService {
   private static final String CLAIM_TYPE = "type";
   private static final String CLAIM_EMAIL = "email";
   private static final String CLAIM_ROLES = "roles";
   private static final String CLAIM_USER_ID = "userId";
   private static final String TYPE_ACCESS = "access";
   private static final String TYPE_REFRESH = "refresh";
   private static final String BEARER_PREFIX = "Bearer ";

   private final JwtProperties jwtProperties;
   private final SecretKey siginingKey;

   public JwtService(JwtProperties jwtProperties){
       this.jwtProperties = jwtProperties;
       byte[] tokenBytes = Decoders.BASE64.decode(jwtProperties.secret());
       this.siginingKey = Keys.hmacShaKeyFor(tokenBytes);
   }

   public String generateAccessToken(User user){
        long nowMs = System.currentTimeMillis();
        long expMs = nowMs + (jwtProperties.accessTokenLifeCycleSeconds()*1000L);

        List<String> roles = user.getRoles().stream().map(Role::getName).toList();

        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(user.getId().toString())
                .setIssuer(jwtProperties.issuer())
                .claim(CLAIM_TYPE,TYPE_ACCESS)
                .claim(CLAIM_EMAIL,user.getEmail())
                .claim(CLAIM_ROLES,roles)
                .claim(CLAIM_USER_ID,user.getId().toString())
                .setIssuedAt(new Date(nowMs))
                .setExpiration(new Date(expMs))
                .signWith(siginingKey)
                .compact();
   }

   public String generateRefreshToken(User user, String jti){
       long nowMs = System.currentTimeMillis();
       long expMs = nowMs + (jwtProperties.refreshTokenTtlSeconds()*1000L);

       return Jwts.builder()
               .setId(jti)
               .setSubject(user.getId().toString())
               .setIssuer(jwtProperties.issuer())
               .claim(CLAIM_TYPE,TYPE_REFRESH)
               .setIssuedAt(new Date(nowMs))
               .setExpiration(new Date(expMs))
               .signWith(siginingKey)
               .compact();
   }

   public Claims parseToken(String token){
       return Jwts.parserBuilder()
               .setSigningKey(siginingKey)
               .requireIssuer(jwtProperties.issuer())
               .build()
               .parseClaimsJws(token)
               .getBody();
   }

   public long getExpiryInSeconds(String token){
       Date expiration = parseToken(token).getExpiration();
       long remaining = expiration.getTime() - System.currentTimeMillis();
       return Math.max(remaining/1000L,0L);
   }

   public Optional<String> extractTokenFromRequest(HttpServletRequest request){
       String header = request.getHeader("Authorization");
       if(header!=null && header.startsWith(BEARER_PREFIX)){
           return Optional.of(header.substring(BEARER_PREFIX.length()));
       }
       return Optional.empty();
   }

    public boolean isAccessToken(String token) {
       Claims claims = parseToken(token);
       return TYPE_ACCESS.equals(claims.get(CLAIM_TYPE));
    }

    public String getUserIdFromToken(String token) {
       return parseToken(token).getSubject();
    }
}
