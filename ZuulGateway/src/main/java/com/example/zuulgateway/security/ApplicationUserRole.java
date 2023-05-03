//package com.example.zuulgateway.security;
//
//import com.google.common.collect.Sets;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//
//import java.util.Set;
//import java.util.stream.Collectors;
//
//import static com.example.zuulgateway.security.ApplicationUserPermissions.*;
//
//public enum ApplicationUserRole {
//    USER(Sets.newHashSet()),
//    ADMIN(Sets.newHashSet(PRODUCT_READ, PRODUCT_WRITE, USER_READ, USER_WRITE)),
//
//    ADMINTRAINEE(Sets.newHashSet(PRODUCT_READ, USER_READ));
//
//    private final Set<ApplicationUserPermissions> permissions;
//
//    ApplicationUserRole(Set<ApplicationUserPermissions> permissions) {
//        this.permissions = permissions;
//    }
//
//    public Set<ApplicationUserPermissions> getPermissions(){
//        return permissions;
//    }
//    public Set<SimpleGrantedAuthority> getGrantedAuthorities (){
//        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
//                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
//                .collect(Collectors.toSet());
//        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
//        return permissions;
//    }
//}
