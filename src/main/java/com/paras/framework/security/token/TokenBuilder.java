package com.paras.framework.security.token;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

/**
 * Utility to build JWT Token.
 * 
 * @author Paras.
 */
public class TokenBuilder {
	
	private static final String IDENTITY = "identity";
	
	public static String generate( Map<String, String> claimMap ) throws JoseException {
		String token = null;
		
		byte[] key = TokenConfiguration.getTokenKey();
		
		String issuer = TokenConfiguration.getIssuer();
		String audience = TokenConfiguration.getAudience();
		String subject = TokenConfiguration.getSubject();
		
		int tokenExpirationTime = TokenConfiguration.getTimeout();
		
		JwtClaims claims = new JwtClaims();
		
		if( StringUtils.isNotBlank(issuer)) {
			claims.setIssuer( issuer );
		}
		
		if( StringUtils.isNotBlank( audience )) {
			claims.setAudience( audience );
		}
		
		if( StringUtils.isNotBlank( subject )) {
			claims.setSubject( subject );
		}
		
		claims.setExpirationTimeMinutesInTheFuture( tokenExpirationTime );
		claims.setIssuedAtToNow();
		
		String mapString = new JSONObject( claimMap ).toString();
		
		claims.setClaim( IDENTITY, encrypt(mapString, TokenConfiguration.getEncryptionKey()));
		
		JsonWebSignature webSignature = new JsonWebSignature();
		
		webSignature.setPayload( claims.toJson() );
		webSignature.setKey( new HmacKey(key) );		
		webSignature.setAlgorithmHeaderValue( AlgorithmIdentifiers.HMAC_SHA512 );	
		
		token = webSignature.getCompactSerialization();
		
		return token;
	}
	
    /**
     * Create a token from object properties.
     * Only non-null & Primitive values will be used.
     
     * @return String token
     * @throws JoseException 
     */
	@SuppressWarnings("rawtypes")
	public static String generate( Class type, Object object ) throws JoseException {
        
        Map<String, String> map = new HashMap<String, String>();
        Method[] methods = type.getMethods();
        
        for( Method method : methods ) {
            
            if( isGetter( method ) ) {
                String propertyName = getProperty( method );
                String value = null;
                
                try{
                    value = getValue( object, method );    
                    map.put( propertyName, value );
                }
                catch( IllegalAccessException ex ) {
                    continue;
                }
                catch( IllegalArgumentException ex ) {
                    continue;
                }
                catch( InvocationTargetException ex ) {
                    continue;
                }
                
            }
        }
        
        return generate( map );
    }
    
    /**
     * Is A Getter Method ?
     */
    @SuppressWarnings("rawtypes")
	private static boolean isGetter( Method method ) {
        
        boolean result = false;
        
        /* A getter method should start with 'get' by convention. */
        if( method.getName().startsWith( "get" )) {
            
            /* And it should not have any arguments as well. */
            if( method.getParameterTypes().length == 0 ) {
                
                Class returnType = method.getReturnType();
                
                /* For our code, we need a primitive property. */
                if( returnType.equals( Integer.class ) || returnType.equals( Character.class ) || returnType.equals( String.class ) || returnType.equals( Boolean.class )) {
                    result = true;
                }
                
            }
            
        }
        
        return result;
    }
    
    /**
     * Retrieve property name from getter method.
     */
    private static String getProperty( Method method ) {
        
        String name = method.getName();
        name = StringUtils.replace(name, "get", "" );
        name = String.valueOf( name.charAt( 0 )).toLowerCase() + name.substring( 1 );
        
        return name;
    }
    
    /**
     * Get String value from getter.
     * @throws InvocationTargetException 
     * @throws IllegalArgumentException 
     * @throws IllegalAccessException 
     */
    @SuppressWarnings("rawtypes")
	private static String getValue( Object object, Method method ) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        
        String result = null;
        Class returnType = method.getReturnType();
        
        Object value = method.invoke( object );
        
        if( returnType.equals( Integer.class )) {
            
            result = Integer.toString( (Integer) value );
            
        } else if ( returnType.equals( Character.class )) {
            
            result = Character.toString( (Character) value );
            
        } else if ( returnType.equals( String.class )) {
            
            result = (String) value;
            
        } else if ( returnType.equals( Boolean.class )) {
            
            result = Boolean.toString( (Boolean ) value );
            
        }
        
        return result;
        
    }
    
    /**
     * Encryption Utility to encrypt sensitive information.
     * @throws JoseException 
     */
    private static String encrypt( String message, String key ) throws JoseException {
        
        Key aesKey = new AesKey( key.getBytes() );
        
        JsonWebEncryption encryption = new JsonWebEncryption();
        
        encryption.setPlaintext( message );
        encryption.setAlgorithmHeaderValue( KeyManagementAlgorithmIdentifiers.A128KW);
        encryption.setEncryptionMethodHeaderParameter( ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256 );
        encryption.setKey( aesKey );
        
        return encryption.getCompactSerialization();
    }
}