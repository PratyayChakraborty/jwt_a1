package com.springjwt.controller;

import com.springjwt.dto.AuthenticationDTO;
import com.springjwt.dto.AuthenticationResponse;
import com.springjwt.services.auth.AuthService;
import com.springjwt.services.auth.AuthServiceImpl;
import com.springjwt.services.auth.jwt.UserDetailsServiceImpl;
import com.springjwt.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.coyote.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class AuthenticationController {

    @Autowired
    private AuthService authService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @PostMapping("/authenticate")
    public AuthenticationResponse creatAuthenticationToken(@RequestBody AuthenticationDTO authenticationDTO, HttpServletResponse response) throws BadCredentialsException, DisabledException, UsernameNotFoundException, IOException {

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationDTO.getEmail(),authenticationDTO.getPassword()));
        }catch (BadCredentialsException e){
            throw   new BadCredentialsException("Incorrect User Name or Password");
        }catch (DisabledException e){
//            throw new DisabledException("");
            response.sendError(HttpServletResponse.SC_NOT_FOUND,"User Is Not Activated");
            return null;
        }

        final UserDetails userDetails= userDetailsService.loadUserByUsername(authenticationDTO.getEmail());

        final  String jwt= jwtUtil.generateToken(userDetails);
        return new AuthenticationResponse(jwt);
    };

}
