package com.example.demo.services.impl;

import java.util.ArrayList;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.entities.UserEntity;
import com.example.demo.repositories.UserRepository;
import com.example.demo.services.UserService;
import com.example.demo.shared.utils;
import com.example.demo.shared.dto.UserDto;
import org.springframework.security.core.userdetails.User;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	UserRepository userRepository;
	
	@Autowired
	utils util ;
	@Autowired
	BCryptPasswordEncoder bCryptPasswordEncoder ;
	
	@Override
	public UserDto createUser(UserDto user) {
		 
	    UserEntity checkUser = userRepository.findByEmail(user.getEmail());
	    if(checkUser != null) throw new IllegalArgumentException("User already exists!");
		UserEntity userEntity = new UserEntity();
		BeanUtils.copyProperties(user, userEntity);
		userEntity.setUserId(util.generateStringId(10));
		userEntity.setEncryptedPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		UserEntity newUser =  userRepository.save(userEntity);
		UserDto userDto = new UserDto();
		BeanUtils.copyProperties(newUser, userDto);
 
		return userDto;
	}

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		UserEntity userEntity = userRepository.findByEmail(email);
		if(userEntity == null) throw new UsernameNotFoundException(email);
		return new User(userEntity.getEmail(), userEntity.getEncryptedPassword(), new ArrayList<>());
	}

	@Override
	public UserDto getUser(String email) {
		UserEntity userEntity = userRepository.findByEmail(email);
		if(userEntity == null) throw new UsernameNotFoundException(email);
		
		UserDto userDto = new UserDto() ;
		BeanUtils.copyProperties(userEntity, userDto);
		return userDto;
	}

}
