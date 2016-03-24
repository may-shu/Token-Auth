package com.paras.framework.security.spring;

import java.util.List;

import org.apache.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

public class TokenAuthentication implements Authentication{
	/**
	 * 
	 */
	private static final long serialVersionUID = 52821042880583507L;

	private static Logger LOGGER = Logger.getLogger(TokenAuthentication.class  );
	
	CurrentUserDetails userDetails;
	private String principal;
    
    private boolean authenticated;
	
	public List<RoleAuthority> getAuthorities() {
		LOGGER.info( "In TokenAuthentication | Starting Execution of getAuthorities ");
		LOGGER.debug("In TokenAuthentication | In getAuthorities | Authorities =" + userDetails.getAuthorities());
		LOGGER.info( "In TokenAuthentication | Finished Execution of getAuthorities" );
		
		return userDetails.getAuthorities();
	}
	
	public String getName() {
		LOGGER.info( "In TokenAuthentication | Starting Execution of getName ");
		LOGGER.debug("In TokenAuthentication | In getAuthorities | Name =" + userDetails.getName());
		LOGGER.info( "In TokenAuthentication | Finished Execution of getName" );
		
		return userDetails.getName();
	}
	
	public String getEmail() {
		LOGGER.info( "In TokenAuthentication | Starting Execution of getEmail ");
		LOGGER.debug("In TokenAuthentication | In getAuthorities | getEmail =" + userDetails.getUsername());
		LOGGER.info( "In TokenAuthentication | Finished Execution of getEmail" );
		
		return userDetails.getUsername();
	}
    
    public Object getCredentials() {
        LOGGER.info( "In TokenAuthentication | Starting Execution of getCredentials ");
		LOGGER.debug("In TokenAuthentication | In getCredentials | Credentials =" + userDetails.getPassword());
		LOGGER.info( "In TokenAuthentication | Finished Execution of getCredentials" );
		
		return userDetails.getPassword();
    }
    
    public Object getDetails() {
        LOGGER.info( "In TokenAuthentication | Starting Execution of getDetails ");
		LOGGER.info( "In TokenAuthentication | Finished Execution of getDetails" );
        
        return userDetails;
    }
    
    public Object getPrincipal() {
    	LOGGER.info( "In TokenAuthentication | Starting Execution of getPrincipal ");
		LOGGER.debug("In TokenAuthentication | In getAuthorities | Principal =" + principal );
		LOGGER.info( "In TokenAuthentication | Finished Execution of getPrincipal" );
		
		return principal;
		
    }
    
    public boolean isAuthenticated() {
        LOGGER.info( "In TokenAuthentication | Starting Execution of isAuthenticated ");
		LOGGER.debug("In TokenAuthentication | In getAuthorities | Authenticated =" + authenticated );
		LOGGER.info( "In TokenAuthentication | Finished Execution of isAuthenticated" );
		
		return authenticated;
    }
    
    public void setAuthenticated(boolean authenticated) throws IllegalArgumentException {
    	LOGGER.info( "In TokenAuthentication | Starting Execution of setAuthenticated ");
		LOGGER.debug("In TokenAuthentication | In getAuthorities | authenticated =" + authenticated );
		LOGGER.info( "In TokenAuthentication | Finished Execution of setAuthenticated" );
		
		this.authenticated = authenticated;
    }
    
    public TokenAuthentication( CurrentUserDetails details ) {
    	this.userDetails = details;
    	this.principal = details.getId();
    }
    
    public TokenAuthentication( UserDetails details ) {
    	this.userDetails = ( CurrentUserDetails ) details;
    	this.principal = this.userDetails.getId();
    }
}
