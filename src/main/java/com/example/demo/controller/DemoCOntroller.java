package com.example.demo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DemoCOntroller {

  @GetMapping("/hello")
  public ResponseEntity<String> sayHello(){
    return ResponseEntity.ok("Hello bokka badu wada");
  }
}