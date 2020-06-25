package com.esports.commons.auth.filters;

import java.util.Date;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;


@Service
public class JwtHandler 
{
	/** */
	private String base64EncodedSecretKey="eXA1dTFvaVBPSVAz";
	/** */
	private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS512;
	
	public JwtHandler() throws Exception
	{

	}
	
	public String verify(String compactJwt) throws AccessDeniedException 
	{
		try 
		{
			JwtParser jwtParser =  Jwts.parser().setSigningKey(base64EncodedSecretKey);
			Claims claims = jwtParser.parseClaimsJws(compactJwt).getBody();
			if(claims == null || claims.getSubject() == null) {
				throw new AccessDeniedException("Access Denied");
			}
			return claims.getSubject();
		} 
		catch (SignatureException e)
		{
			e.printStackTrace();
			throw new AccessDeniedException("Access Denied");
		}
	}
	
	public String verifyTokenAndGetUserId(String compactJwt) throws AccessDeniedException 
	{
		try 
		{
			JwtParser jwtParser =  Jwts.parser().setSigningKey(base64EncodedSecretKey);
			Claims claims = jwtParser.parseClaimsJws(compactJwt).getBody();
			if(claims == null || claims.getSubject() == null) {
				throw new AccessDeniedException("Access Denied");
			}
			if(claims.getAudience() ==null || Integer.parseInt(claims.getAudience()) <= 0) {
				throw new AccessDeniedException("Access Denied");
			}
			return claims.getAudience();
		} 
		catch (SignatureException e)
		{
			e.printStackTrace();
			throw new AccessDeniedException("Access Denied");
		}
	}

	public String verifyAndGetUserId(String compactJwt) throws AccessDeniedException
	{
		try
		{
			JwtParser jwtParser =  Jwts.parser().setSigningKey(base64EncodedSecretKey);
			return jwtParser.parseClaimsJws(compactJwt).getBody().getAudience();
		}
		catch (SignatureException e)
		{
			e.printStackTrace();
			throw new AccessDeniedException("Access Denied");
		}
	}

	public String createJwtToken(String email, String name, String userId) throws Exception
	{
		// Claims Part
		Claims claims = Jwts.claims();
		claims.setSubject(email);
		claims.setAudience(userId);
		claims.setIssuedAt(new Date(System.currentTimeMillis()));
		claims.setIssuer("opleague.com");
		claims.setExpiration(new Date(System.currentTimeMillis() + 172800000));
		claims.put("name", name);
		// Get The URL Safe JWT Token
		String jwtToken = Jwts.builder().setClaims(claims).signWith(signatureAlgorithm, base64EncodedSecretKey).compact();
		return jwtToken;
	}
	
	public String verifyTokenAndGetUserName(String compactJwt) throws AccessDeniedException 
	{
		try 
		{
			JwtParser jwtParser =  Jwts.parser().setSigningKey(base64EncodedSecretKey);
			Claims claims = jwtParser.parseClaimsJws(compactJwt).getBody();
			if(claims == null || claims.getSubject() == null) {
				throw new AccessDeniedException("Access Denied");
			}
			if(claims.getAudience() ==null || Integer.parseInt(claims.getAudience()) <= 0) {
				throw new AccessDeniedException("Access Denied");
			}
			if(claims.get("name") == null) {
				throw new AccessDeniedException("Access Denied");
			}
			return (String) claims.get("name");
		} 
		catch (SignatureException e)
		{
			e.printStackTrace();
			throw new AccessDeniedException("Access Denied");
		}
	}

}