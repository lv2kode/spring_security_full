package com.lv2code.spring.security.dao;

import java.util.Optional;

import com.lv2code.spring.security.auth.ApplicationUser;

public interface ApplicationUserDao {
	
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
