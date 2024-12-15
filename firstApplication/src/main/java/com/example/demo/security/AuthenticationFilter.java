package com.example.demo.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.demo.SpringApplicationContext;
import com.example.demo.requests.UserLoginRequest;
import com.example.demo.services.UserService;
import com.example.demo.shared.dto.UserDto;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;

import java.util.ArrayList;
import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AuthenticationFilter  extends UsernamePasswordAuthenticationFilter{

	private final AuthenticationManager authenticationManager;
 	public AuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
 	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
			throws AuthenticationException {
		try {

			UserLoginRequest creds = new ObjectMapper().readValue(req.getInputStream(), UserLoginRequest.class);

			return authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(creds.getEmail(), creds.getPassword(), new ArrayList<>()));

		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
        
        String userName = ((User) auth.getPrincipal()).getUsername(); 
        System.out.println(userName);

       
  
       
        String token = Jwts.builder()
                .setClaims(Map.of("sub", userName))  // Setting the subject (userName)
                .setSubject(userName)
                .setExpiration(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
                .signWith(SecurityConstants.SECRET_KEY)
                .compact();
        UserService userService = (UserService)SpringApplicationContext.getBean("userServiceImpl");
        
        UserDto userDto = userService.getUser(userName);
        
        System.out.println(token);
        // Add the token in the response header
        res.addHeader(SecurityConstants.HEADER_STRING, SecurityConstants.TOKEN_PREFIX + token);
        res.addHeader("user_id", userDto.getUserId());
        System.out.println(userDto.getUserId());
    }
}
