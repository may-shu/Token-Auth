package com.paras.framework.security.token;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.paras.framework.security.spring.CurrentUserDetails;
import com.paras.framework.security.spring.RoleAuthority;

/**
 * Mapper to turn a map of claims into a UserDetails (Spring) instance.
 * It will try its best to map.
 * 
 * @author Paras
 */
public class TokenToUserDetailsMapper {
    
    private static final String PRINCIPALS = "id, email, pricipal, userId";
    private static final String NAME = "name, firstName, lastName, fullName";
    private static final String ROLE = "role, roles, authority, authorities";
	
    public static CurrentUserDetails map( Map<String, String> claims ) {
        
        CurrentUserDetails details = new CurrentUserDetails();
        List<RoleAuthority> roles = new ArrayList<RoleAuthority>();
        
        for( String key : claims.keySet() ) {
            
            if( isKeyPrincipal( key )) {
                details.setId( claims.get( key ));
                continue;
            }
            
            if( isKeyName( key )) {
                details.setName( claims.get( key ));
                continue;
            }
            
            if( isKeyRole( key )) {
                roles.add( new RoleAuthority( claims.get( key )));
                continue;
            }
            
        }
        
        details.setAuthorities( roles );
        
        details.setAccountNonExpired( true );
				details.setAccountNonLocked( true );
				details.setEnabled( true );
        
        details.setCredentialsNonExpired( true );
				details.setPassword( null );
				
		return details;
        
    }
    
    private static boolean isKeyPrincipal( String key ) {
        return PRINCIPALS.contains( key.toLowerCase() );
    }
    
    private static boolean isKeyName( String key ) {
        return NAME.contains( key.toLowerCase() );
    }
    
    private static boolean isKeyRole( String key ) {
        return ROLE.contains( key.toLowerCase() );
    }
    
}