package com.paras.framework.security.filter;

import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import org.jose4j.jwt.consumer.InvalidJwtException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.paras.framework.security.exception.NoTokenFoundException;

/**
 * Utility class used by Filter to extract token from request.
 * And later use the token to form authentication object for subsequenct requests.
 
 * @Author Paras.
 */
class FilterUtil {

    private static final String AUTHORIZATION = "Authorization";
    private static final String BEARER = "Bearer ";
    
    @SuppressWarnings("unchecked")
	public static String getToken() throws NoTokenFoundException, InvalidJwtException {
        boolean tokenFound = false;
        
        ServletRequestAttributes attributes = ( ServletRequestAttributes ) RequestContextHolder.currentRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        
        Enumeration<String> headers = request.getHeaderNames();
        String token = null;
        
        while( headers.hasMoreElements() ) {
            String header = headers.nextElement();
            
            if( header.equalsIgnoreCase( AUTHORIZATION )) {
                String tokenWithBearer = request.getHeader( header );
                
                if( tokenWithBearer.startsWith( BEARER )) {
                    tokenFound = true;
                    token = tokenWithBearer.replace( BEARER, "");
                    
                    break;
                } else {                	
                    throw new InvalidJwtException( "Token doesn't starts with " + BEARER );
                }
            }
        }
        
        if( !tokenFound ) {
			throw new NoTokenFoundException( "Request Doesn't has " + AUTHORIZATION + " header." );
		}
        
        return token;
    }
}
