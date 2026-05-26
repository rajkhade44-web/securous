package com.securous.backend.security;

import com.securous.backend.security.jwt.JwtProperties;
import com.securous.backend.security.jwt.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CookieService {
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    public void attachRefreshCookie(HttpServletResponse response,String token,long maxAge){
        response.addHeader(HttpHeaders.SET_COOKIE,buildCookie(token,maxAge).toString());
    }

    public void clearRefreshCookie(HttpServletResponse response){
        response.addHeader(HttpHeaders.SET_COOKIE,buildCookie("",0).toString());
    }

    public void addNoStoreHeaders(HttpServletResponse response){
        response.setHeader("Cache-Control","no-store");
        response.setHeader("Pragma","no-cache");
    }

    private ResponseCookie buildCookie(String value,long maxAge){
        ResponseCookie.ResponseCookieBuilder builder=ResponseCookie
                .from(jwtProperties.cookieName(),value)
                .httpOnly(jwtProperties.cookieHttpOnly())
                .maxAge(maxAge)
                .sameSite(jwtProperties.cookieSameSite())
                .path("/");
        if(jwtProperties.cookieDomain()!=null && !jwtProperties.cookieDomain().isBlank()){
            builder.domain(jwtProperties.cookieDomain());
        }
        return builder.build();
    }
}
