package com.paras.framework.security.spring;

import org.springframework.security.core.GrantedAuthority;

public class RoleAuthority implements GrantedAuthority{
    
    /**
	 * 
	 */
	private static final long serialVersionUID = 6637248197876008746L;
	private String authority;
	
	public RoleAuthority( String authority ) {
		this.authority = authority;
	}
    
    public void setAuthority( String authority ) {
        this.authority = authority;
    }

	@Override
	public String getAuthority() {
		return authority;
	}
	
}
