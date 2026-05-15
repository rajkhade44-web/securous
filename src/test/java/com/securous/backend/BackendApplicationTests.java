package com.securous.backend;

import com.securous.backend.security.jwt.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;


import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class BackendApplicationTests {

	@Autowired
	private JwtService jwtService;

	@Test
	public void shouldGenerateJwt(){
		String token = jwtService.generateToken("test@example.com");
		System.out.println(token);
	}

	// Happy Path: parse a valid token
	@Test
	void shouldParseValidToken(){
		String token = jwtService.generateToken("alice@example.com");
		Claims claims = jwtService.parseToken(token);
		assertEquals("alice@example.com",claims.getSubject());
	}

	// Expired token – isTokenExpired returns true
	@Test
	void shouldDetectExpiredToken() throws Exception{
		String token = jwtService.generateTokenWithExpiration("bob@example.com",1L);
		Thread.sleep(1500);
		assertTrue(jwtService.isTokenExpired(token));
	}

	@Test
	void shouldThrowOnTamperedToken(){
		String token = jwtService.generateToken("raj@example.com");
		String tampered = token.substring(0, token.length() - 1) + "X";
		assertThrows(SignatureException.class,()->jwtService.parseToken(tampered));
	}


}