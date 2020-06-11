package com.esports.commons.auth.filters;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class AccessDeniedException extends RuntimeException 
{
	/** */
	private static final long serialVersionUID = 1L;

	/**
	 * 
	 * @param msg String
	 */
	public AccessDeniedException(String msg) 
	{
		super(msg);
	}

	/**
	 * 
	 * @param msg
	 * @param t
	 */
	public AccessDeniedException(String msg, Throwable t)
	{
		super(msg, t);
	}
}
