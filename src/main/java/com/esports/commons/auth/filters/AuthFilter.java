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
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;


@Component
public class AuthFilter extends GenericFilterBean
{
	/** */
	private static final Logger logger = LoggerFactory.getLogger(AuthFilter.class);
	/** */
	private static final String HEADER_AUTH_TOKEN_KEY = "E-Auth-Token";
	/***/
	private static final String HEADER_AUTH_TOKEN_VALUE = "fpoa43edty5";
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)throws IOException, ServletException 
	{
		logger.debug("Auth Filter - Enter");
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		
		String ipAddress = httpRequest.getRemoteAddr();
		String userAgent = httpRequest.getHeader("User-Agent");
		String cpOrigin = httpRequest.getHeader("cp-origin");
		
		if(logger.isTraceEnabled())
			logger.trace("ipAddress:" + ipAddress + " path:" + httpRequest.getServletPath() + " cpOrigin:" + cpOrigin +  " User-Agent:" + userAgent);
		
		boolean authenticated  = checkToken(httpRequest, httpResponse);
		if(authenticated)
		{
			chain.doFilter(request, response);
		}
		else
		{
			String method = httpRequest.getMethod();
			if(method != null && method.equalsIgnoreCase(HttpMethod.OPTIONS.name()))
			{
				logger.debug("Options HTTP Method Allowed For ipAddress:" + ipAddress + " path:" + httpRequest.getServletPath() + " cpOrigin:" + cpOrigin +  " User-Agent:" + userAgent);
				
				chain.doFilter(request, response);
			}
			else
			{
				httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			}
			
			if(method != null && !method.equalsIgnoreCase(HttpMethod.OPTIONS.name()))
				logger.warn(" *** Invalid " + HEADER_AUTH_TOKEN_KEY + " path:" + httpRequest.getServletPath() + " method:" + method + " ipAddress:" + ipAddress + " cpOrigin:" + cpOrigin + " User-Agent:" + userAgent);
		}
		
		if(logger.isDebugEnabled())
			logger.debug("Auth Filter - Exit");
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
	private boolean checkToken(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException
	{
		String token = httpRequest.getHeader(HEADER_AUTH_TOKEN_KEY);
		if (token != null && token.equalsIgnoreCase(HEADER_AUTH_TOKEN_VALUE)) 
		{
			return true;
		} 		
		return false;
	}
}
