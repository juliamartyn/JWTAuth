package com.juliamartyn.controller.request;

import java.util.Set;

public class SignUpRequest {

    private String username;
    private String password;
    private Set<String> role;

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
    
    public Set<String> getRole() {
    	return this.role;
    }
}