package com.paras.framework.security.token;

import java.io.IOException;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class TokenValidator {
	
	private static Logger LOGGER = Logger.getLogger( TokenValidator.class );

    /**
     * Static JwtConsumer Object to validate the JWT.
     */
	private static JwtConsumer consumer = null;

    /** 
     * Utility Method to create a Consumer if it doesn't exists,
     * otherwise, return existing one.
     */
	private static JwtConsumer getConsumer() {

		if( consumer == null ) {
			String issuer = TokenConfiguration.getIssuer();
			String audience = TokenConfiguration.getAudience();
			String subject = TokenConfiguration.getSubject();

			byte[] key = TokenConfiguration.getTokenKey();

			JwtConsumerBuilder consumerBuilder = new JwtConsumerBuilder()
			.setRequireExpirationTime()
			.setRequireSubject()			
			.setVerificationKey( new HmacKey(key) );

			if( StringUtils.isNotBlank( subject )) {
				consumerBuilder.setExpectedSubject( subject );
			}

			if( StringUtils.isNotBlank( issuer )) {
				consumerBuilder.setExpectedIssuer( issuer );
			}

			if( StringUtils.isNotBlank( audience )) {
				consumerBuilder.setExpectedAudience( audience );
			}

			consumer = consumerBuilder.build();
		}

		return consumer;
	}

    /**
     * Validate and return custom claims passed.
     * @param token to validate.
     *
     * @return Map of custom claims
     */
	public static Map<String, String> validate( String token ) throws InvalidJwtException, JoseException{


		JwtClaims claims = getConsumer().processToClaims( token );
		return decrypt( (String) claims.getClaimValue("identity"));

	}
    
    /**
     * Validate and return custom claims passed.
     * @param type Class in whichi payload needs to be stored.
     * @param token token to validate.
     *
     * @return Instance of type.
     * @throws IOException 
     * @throws JsonMappingException 
     * @throws JsonParseException 
     * @throws InvalidJwtException 
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
	public static Object validate( Class holder, String token ) throws JoseException, JsonParseException, JsonMappingException, IOException, InvalidJwtException {
    	JwtClaims jClaims = getConsumer().processToClaims( token );
        Map<String, String> claims = decrypt( (String) jClaims.getClaimValue("identity"));
        
        JSONObject json = new JSONObject( claims );
        ObjectMapper mapper = new ObjectMapper();
        
        return mapper.readValue( json.toString(), holder );
    }
    
    /**
     * We store custom payload in identity claim in encrypted format.
     * Here, we decrypt the payload and return obtained map.
     */
    private static Map<String, String> decrypt( String identity ) throws JoseException {
    	
    	Map<String, String> claims = null;
        
        String aesKey = TokenConfiguration.getEncryptionKey();
        Key key = new AesKey( aesKey.getBytes() );
        
        JsonWebEncryption encryption = new JsonWebEncryption();
        encryption.setKey( key );
        encryption.setCompactSerialization( identity );
        
        String payLoad = encryption.getPayload();
        
        JsonFactory factory = new JsonFactory();
        ObjectMapper mapper = new ObjectMapper( factory );
        
        TypeReference<HashMap<String, String>> typeRef = new TypeReference<HashMap<String, String>>(){};
        
        try{
        	claims = mapper.readValue( payLoad, typeRef );
        }
        catch( Exception ex ) {
        	LOGGER.error( "In TokenValidator | decrypt | "  + ex.getMessage());
        	throw new JoseException( ex.getMessage());
        }
        
        return claims;
        
    }
}
