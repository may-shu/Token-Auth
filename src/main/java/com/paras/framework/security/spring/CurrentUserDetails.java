package com.paras.framework.security.spring;

import java.util.List;

import org.springframework.security.core.userdetails.UserDetails;

public class CurrentUserDetails implements UserDetails{
	/**
	 * 
	 */
	private static final long serialVersionUID = 2719049603532086727L;
	private List<RoleAuthority> authorities;;
	private String password;
	private String username;
	
	private String id;
	private String name;
	
	boolean accountNonExpired;
    boolean accountNonLocked;
    boolean credentialsNonExpired;
    boolean enabled;
    
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public List<RoleAuthority> getAuthorities() {
		return authorities;
	}
	public void setAuthorities(List<RoleAuthority> authorities) {
		this.authorities = authorities;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public void setAccountNonExpired(boolean accountNonExpired) {
		this.accountNonExpired = accountNonExpired;
	}
	public void setAccountNonLocked(boolean accountNonLocked) {
		this.accountNonLocked = accountNonLocked;
	}
	public void setCredentialsNonExpired(boolean credentialsNonExpired) {
		this.credentialsNonExpired = credentialsNonExpired;
	}
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	public String getPassword() {
		return password;
	}
	public String getUsername() {
		return username;
	}
	public boolean isAccountNonExpired() {
		return accountNonExpired;
	}
	public boolean isAccountNonLocked() {
		return accountNonLocked;
	}
	public boolean isCredentialsNonExpired() {
		return credentialsNonExpired;
	}
	public boolean isEnabled() {
		return enabled;
	}
    
    
}
