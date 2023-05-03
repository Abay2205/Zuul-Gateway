package com.example.zuulgateway.service;

import com.example.zuulgateway.Entity.Role;
import com.example.zuulgateway.Entity.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers();

    User findUserById(Long id);

    void deleteUser(Long id);

    User updateUser(User user, Long id);
}
