package com.security.configuration;


import com.google.common.collect.Sets;

import java.util.Set;

import static com.security.configuration.KisiPermission.*; //Kisi permission icindeki herseyi ekledik USER_READ vsyi gormesi icin

public enum KisiRole {
    //kisi rolleri yani izinleri set gibi bir collectionda tutuluor
    USER(Sets.newHashSet(USER_READ)),
    ADMIN(Sets.newHashSet(ADMIN_READ,ADMIN_WRITE));

    private Set<KisiPermission> kisiPermission;

    public Set<KisiPermission> getKisiPermission() {
        return kisiPermission;
    }

    KisiRole(Set<KisiPermission> kisiPermission) {
        this.kisiPermission = kisiPermission;
    }
}
