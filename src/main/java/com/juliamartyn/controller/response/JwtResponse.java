package com.juliamartyn.controller.response;

public class JwtResponse {
    private String token;
    private String type = "Bearer";

    public JwtResponse(String accessToken) {
        this.token = accessToken;
    }
}