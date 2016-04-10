package com.paras.framework.security.logger;

import org.apache.log4j.Logger;

public class AuditLogger {

	private static Logger logger = Logger.getLogger( "clocery.audit" );
	
	
	public static void log( String message ) {
		logger.info( message );
	}
	
	public static void log( Object message ) {
		logger.info( message );
	}
}
