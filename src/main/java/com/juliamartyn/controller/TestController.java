package com.juliamartyn.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

	@GetMapping("/all")
	public String all() {
		return "This page is available to everyone";
	}

	@GetMapping("/user")
	@PreAuthorize("hasAuthority('ROLE_ADMIN') or hasAuthority('ROLE_USER')")
	public String user() {
		return "This page is available to all authorize users";
	}

	@GetMapping("/admin")
	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	public String admin() {
		return "This page is available to authorize users who have role ADMIN only";
	}
}