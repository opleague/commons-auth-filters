package com.esports.commons.auth.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import com.esports.commons.auth.filters.JwtHandler;


@Component
public class JwtAuthFilter extends GenericFilterBean
{
	/** */
	private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);
	/** */
	private static final String HEADER_JWT_TOKEN = "E-JWT-Token";

	@Autowired
	private JwtHandler jwtHandler;
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)throws IOException, ServletException 
	{
		logger.debug("JwtAuthFilter - Enter");
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		boolean authenticated  = checkJwtToken(httpRequest, httpResponse);
		if(authenticated)
		{
			
			chain.doFilter(request, response);
		}
		else
		{
			String ipAddress = httpRequest.getRemoteAddr();
			String userAgent = httpRequest.getHeader("User-Agent");
			String cpOrigin = httpRequest.getHeader("cp-origin");
			String method = httpRequest.getMethod();
			if(method != null && method.equalsIgnoreCase(HttpMethod.OPTIONS.name()))
			{
				if(logger.isDebugEnabled())
					logger.debug("Options HTTP Method Allowed For ipAddress:" + ipAddress + " cpOrigin:" + cpOrigin +  " User-Agent:" + userAgent);
				
				chain.doFilter(request, response);
			}
			else
			{
				httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			}
			
			if(method != null && !method.equalsIgnoreCase(HttpMethod.OPTIONS.name()))
				logger.warn(" *** Invalid " + HEADER_JWT_TOKEN + " path:" + httpRequest.getServletPath() + " method:" + method  + " ipAddress:" + ipAddress + " cpOrigin:" + cpOrigin + " User-Agent:" + userAgent);
		}
		
		if(logger.isDebugEnabled())
			logger.debug("JwtAuthFilter - Exit");
	}
	
	/**
	 * 
	 * @param httpRequest HttpServletRequest
	 * @param httpResponse HttpServletResponse
	 * 
	 * @return boolean
	 * 
	 * @throws IOException
	 */
	private boolean checkJwtToken(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException
	{
		String token = httpRequest.getHeader(HEADER_JWT_TOKEN);
		
		if (token == null) 
		{
			return false;
		} 
		
		try 
		{
			 String email=jwtHandler.verify(token);
			 httpRequest.setAttribute("userEmail", email);
			 return true;
		}
		catch (AccessDeniedException e)
		{
			e.printStackTrace();
			logger.warn(" *** Invalid Jwt Token " + token);
		}
		return false;
	}
}
