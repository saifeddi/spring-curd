package com.example.demo.security;
import java.io.IOException;
import java.util.ArrayList;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

 
public class AuthorizationFilter extends BasicAuthenticationFilter {
	 private final SecretKey key;
    public AuthorizationFilter(AuthenticationManager authManager) {
        super(authManager);
        this.key = Keys.secretKeyFor(SignatureAlgorithm.HS512); 
     } 
    
    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        
        String header = req.getHeader(SecurityConstants.HEADER_STRING);
        
        if (header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }
        
        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }   
    
    
    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(SecurityConstants.HEADER_STRING);
        
        if (token != null) {
            
            token = token.replace(SecurityConstants.TOKEN_PREFIX, "");
            

             
            Claims body = Jwts.parser()
            		.setSigningKey(SecurityConstants.SECRET_KEY)
            		.build()
            		.parseSignedClaims(token)
            		.getPayload();
            String user = body.getSubject();
            System.out.print("***************************************");
            System.out.print(user);
            if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
            }
            
            return null;
        }
        
        return null;
    }
    

}