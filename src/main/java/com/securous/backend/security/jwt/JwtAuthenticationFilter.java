package com.securous.backend.security.jwt;

import com.securous.backend.security.CustomUserDetails;
import com.securous.backend.security.CustomUserDetailsService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final CustomUserDetailsService customUserDetailsService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token=jwtService.extractTokenFromRequest(request).orElse(null);

        if(token==null){
            filterChain.doFilter(request,response);
            return;
        }

        if(!jwtService.isAccessToken(token)){
            filterChain.doFilter(request,response);
            return;
        }

        if(SecurityContextHolder.getContext().getAuthentication()!=null){
            filterChain.doFilter(request,response);
            return;
        }

        try {
            String userId = jwtService.getUserIdFromToken(token);
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(userId);

            if(!userDetails.isEnabled()){
                filterChain.doFilter(request,response);
                return;
            }

            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,null,userDetails.getAuthorities()
            );

            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authToken);
            log.info("Authenticated user {}",userId);
        } catch (JwtException e){
            log.warn("JWT rejected: {}",e.getMessage());
        }
        filterChain.doFilter(request,response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String uri = request.getRequestURI();
        return uri.startsWith("/api/v1/auth") || uri.startsWith("/v3/api-docs");
    }
}
