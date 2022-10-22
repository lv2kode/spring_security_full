package com.lv2code.spring.security.dao;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;
import com.lv2code.spring.security.ApplicationUserRole;
import com.lv2code.spring.security.auth.ApplicationUser;

@Repository("fake")
public class FakeApplicationUserDaoImpl implements ApplicationUserDao {
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public FakeApplicationUserDaoImpl(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		// TODO Auto-generated method stub
		return getApplicationUsers()
				.stream()
				.filter(applicationUser -> username.equals(applicationUser.getUsername()))
				.findFirst();
	}
	
	private List<ApplicationUser> getApplicationUsers() {
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
					new ApplicationUser(
							ApplicationUserRole.STUDENT.getGrantedAuthorities(), 
							passwordEncoder.encode("password"), 
							"annasmith", 
							true, 
							true, 
							true, 
							true
					),
					new ApplicationUser(
							ApplicationUserRole.ADMIN.getGrantedAuthorities(), 
							passwordEncoder.encode("password"),
							"linda", 
							true, 
							true, 
							true, 
							true
					),
					new ApplicationUser(
							ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(), 
							passwordEncoder.encode("password"),
							"tom", 
							true, 
							true, 
							true, 
							true
					)
				);
		return applicationUsers;
	}

}
