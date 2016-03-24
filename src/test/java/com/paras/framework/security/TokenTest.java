package com.paras.framework.security;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;

import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.paras.framework.security.token.TokenBuilder;
import com.paras.framework.security.token.TokenConfiguration;
import com.paras.framework.security.token.TokenValidator;

public class TokenTest {
	
	private static final String ISSUER = "Paras.";
    private static final String AUDIENCE = "You and me.";
    private static final String SUBJECT = "Identity";
    private static final int TIMEOUT = 30;
    
    private static final String TOKEN_KEY = "One ring to rule them all. One ring to find them all. One ring to bring them all. And in the darkness, bind them.";
    private static final String ENCRYPTION_KEY = "DumbleDore : Have you grown to care for the boy ? Snape : For Him ? Expecto patronum ! DumbleDore : After All this time ? Snape : Always.";

	@Test
	public void testTokenGenerationAndVerification() throws JoseException, InvalidJwtException, JsonParseException, JsonMappingException, IOException {
		
		TokenConfiguration.setTokenKey( TOKEN_KEY );
		
        TokenConfiguration.setIssuer( ISSUER );
        TokenConfiguration.setAudience( AUDIENCE );
        TokenConfiguration.setSubject( SUBJECT );
        TokenConfiguration.setTimeout( TIMEOUT );
        
        TokenConfiguration.setEncryptionKey( ENCRYPTION_KEY );
        
        Map<String, String> theMap = new HashMap<String, String>();
        
        theMap.put( "location", "The Shire" );
        theMap.put( "danger", "Mordor" );
        
        String token = TokenBuilder.generate( theMap );
       
        Lord rings = ( Lord )TokenValidator.validate(Lord.class, token);
        
        Assert.assertEquals( "The Shire", rings.getLocation());
        Assert.assertEquals( "Mordor", rings.getDanger());
	}	
}
