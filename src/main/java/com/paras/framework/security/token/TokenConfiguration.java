package com.paras.framework.security.token;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Token Configuration Holder.
 * We will hold information like Issuer, Audience, Time-out time and key here.
 * @author Paras
 *
 */
public class TokenConfiguration {
	
	private static Logger LOGGER = Logger.getLogger( TokenConfiguration.class );
		
	/**
	 * Key to be used for signature setting and verification.
	 */
	private static String tokenKey;
    
    /**
     * Key to be used for value encryption and decryption.
     */
    private static String encryptionKey;
	
	/**
	 * Issuer of token.
	 */
	private static String issuer;
	
	/**
	 * Audience of token.
	 */
	private static String audience;
	
	/**
	 * Token Time-out time.
	 */
	private static int timeout;
	
	/**
	 * Token Subject 
	 */
	public static String subject;
	
	/**
	 * Configuration file path.
	 */
	private String config;
	
	public static byte[] getTokenKey() {
        if( tokenKey == null ) {
            return null;
        }
        
        return tokenKey.getBytes();
    }
    
    public static String getEncryptionKey() {
        if( encryptionKey == null ) {
            return null;
        }
        
        return encryptionKey;
    }

	public static String getIssuer() {
		return issuer;
	}

	public static String getAudience() {
		return audience;
	}

	public static int getTimeout() {
		return timeout;
	}
	
	public static String getSubject() {
		return subject;
	}
	
	public static void setTokenKey( String keyToUse ) {
        TokenConfiguration.tokenKey = keyToUse;
    }
    
	public static void setIssuer(String issuer) {
		TokenConfiguration.issuer = issuer;
	}

	public static void setAudience(String audience) {
		TokenConfiguration.audience = audience;
	}

	public static void setTimeout(int timeout) {
		TokenConfiguration.timeout = timeout;
	}

	public static void setSubject(String subject) {
		TokenConfiguration.subject = subject;
	}
	
	public static void setEncryptionKey( String encryptionKey ) {
        TokenConfiguration.encryptionKey = encryptionKey.substring(0, 16);
	}
	
	public void setConfig( String config ) {
		this.config = config;
	}
	
	public String getConfig() {
		return this.config;
	}
	
	/**
	 * Init method to set up token configuration by reading a JSON file on classpath.
	 * token-auth.json
	 */
	public void init() throws IOException {
        if( StringUtils.isEmpty( this.config )) {
            init( "token-auth.json" );
        } else {
            init( config );
        }
	}
	
	public void init( String path ) throws IOException{
		try{
			Map<String, String> confMap = null;
			InputStream configStream = getClass().getClassLoader().getResourceAsStream( path );
			
			JsonFactory factory = new JsonFactory();
			ObjectMapper mapper = new ObjectMapper( factory );
			
			TypeReference<HashMap<String, String>> typeRef = new TypeReference<HashMap<String, String>>(){};
			confMap = mapper.readValue( configStream, typeRef );
			
			String tokenKey = "tokenKey";
			String encryptionKey = "encryptionKey";
			String issuer = "issuer";
			String audience = "audience";
			String timeout = "timeout";
			String subject = "subject";
            
            TokenConfiguration.setTokenKey( confMap.get( tokenKey ));
            TokenConfiguration.setEncryptionKey( confMap.get( encryptionKey ));
            TokenConfiguration.issuer = confMap.get( issuer );
            TokenConfiguration.audience = confMap.get( audience );
            TokenConfiguration.timeout = Integer.parseInt( confMap.get( timeout ));
            TokenConfiguration.subject = confMap.get( subject );
            
		}
		catch( IOException ex ){
			LOGGER.info( "In TokenConfiguration | Caught IOException | " + ex.getMessage() );
			throw new IOException( ex.getMessage() );
		}
	}
}