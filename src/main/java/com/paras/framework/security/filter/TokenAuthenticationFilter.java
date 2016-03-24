package com.paras.framework.security.filter;

import java.io.IOException;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import com.paras.framework.security.base.Response;
import com.paras.framework.security.exception.NoTokenFoundException;
import com.paras.framework.security.spring.TokenAuthentication;
import com.paras.framework.security.token.TokenToUserDetailsMapper;
import com.paras.framework.security.token.TokenValidator;

/**
 * Filter to intercept all requests that expects user to be authenticated.
 * Filter will expect a Authorization Header in the request.
 * If found, will try to create authenticatin object out of it.
 * Otherwise, will throw a Access Denied Error.

 * @author Paras.
 */
public class TokenAuthenticationFilter implements Filter {
	private static Logger LOGGER = Logger.getLogger( TokenAuthenticationFilter.class );
	
	private static final String TOKEN_EXPIRED_STRING = "The JWT is no longer valid - the evaluation time";

	private static final int AUTHORIZATION_ERROR_STATUS = 403;
	private static final int AUTHENTICATION_ERROR_STATUS = 401;

	@Override
	public void init( FilterConfig config ) {}

	@Override
	public void destroy() {}

	@Override
	public void doFilter( ServletRequest request, ServletResponse response, FilterChain chain ) throws IOException, ServletException {
		LOGGER.info( "In TokenAuthenticationFilter | Starting Execution of doFilter" );

		String token = null;
		HttpServletResponse httpResponse = ( HttpServletResponse ) response;

		try{
			token = FilterUtil.getToken();
			Map<String, String> claims = TokenValidator.validate( token );
			UserDetails user = TokenToUserDetailsMapper.map( claims );

			Authentication auth = new TokenAuthentication( user );

			auth.setAuthenticated( true );

			SecurityContextHolder.getContext().setAuthentication( auth );
			chain.doFilter( request, response );
		}
		catch( NoTokenFoundException ex ) {
			LOGGER.error( "In TokenAuthenticationFilter | NoTokenFoundException " + ex.getMessage());

			Response res = new Response();
			res.setMessage( "No Authentication Token Found" );

			
			try {
				httpResponse.getWriter().write( res.toJSON() );
				httpResponse.getWriter().flush();
			} 
			catch (IOException e) {				
				LOGGER.error( e.getMessage() );
			}
		}
		catch( InvalidJwtException ex ) {
			LOGGER.error( "In TokenAuthenticationFilter | InvalidJwtException " + ex.getMessage());
			
			Response res = null;
			
			if( ex.getMessage().contains( TOKEN_EXPIRED_STRING )) {
				res = new Response();
				res.setMessage( "Session Has Expired.");
				res.setFlag( "SE" );
				
				httpResponse.setStatus( AUTHENTICATION_ERROR_STATUS );
			} else {

				res = new Response();			
				res.setMessage( "No Authentication Token Found" );
				
				httpResponse.setStatus( AUTHENTICATION_ERROR_STATUS );
			
			}

			
			try {
				httpResponse.getWriter().write( res.toJSON() );
				httpResponse.getWriter().flush();
			} 
			catch (IOException e) {				
				LOGGER.error( e.getMessage() );
			}
		}
		catch( JoseException ex ) {
			LOGGER.error( "In TokenAuthenticationFilter | JoseException " + ex.getMessage());

			Response res = new Response();
			res.setMessage( "No Authentication Token Found" );

			httpResponse.setStatus( AUTHORIZATION_ERROR_STATUS );
			try {
				httpResponse.getWriter().write( res.toJSON() );
				httpResponse.getWriter().flush();
			} 
			catch (IOException e) {				
				LOGGER.error( e.getMessage() );
			}
		}


		LOGGER.info( "In TokenAuthenticationFilter | Finished Execution of doFilter" );
	}
}
