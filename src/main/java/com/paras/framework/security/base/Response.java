package com.paras.framework.security.base;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A simple and small weighted data model to represent API result.
 
 * @author Paras.
 */
public class Response {
    private String flag;
    private String message;
    private Object data;
	public String getFlag() {
		return flag;
	}
	public void setFlag(String flag) {
		this.flag = flag;
	}
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
	public Object getData() {
		return data;
	}
	public void setData(Object data) {
		this.data = data;
	}
    
    public String toJSON() {

		try{
			ObjectMapper mapper = new ObjectMapper();
			return mapper.writeValueAsString( this );
		}catch( JsonGenerationException ex ) {
			return null;
		}catch( JsonMappingException ex ) {
			return null;
		}catch( IOException ex ) {
			return null;
		}		
	}
}
