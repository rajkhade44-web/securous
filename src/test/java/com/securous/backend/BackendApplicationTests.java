package com.securous.backend;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class BackendApplicationTests {

	@Value("${DATABASE_USER}")
	private String databaseUser;

	@Value("${JWT_SECRET}")
	private String jwtSecret;

	@Test
	void testEnvVariables() {

		System.out.println("DATABASE_USER = " + databaseUser);

		System.out.println("JWT_SECRET = " + jwtSecret);
	}
}