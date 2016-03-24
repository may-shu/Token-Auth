package com.paras.framework.security.exception;

public class NoTokenFoundException extends Exception{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public NoTokenFoundException() {
		super();
	}
	
	public NoTokenFoundException(String message ){
		super( message );
	}
}
