/**
 * Copyright (c) 2013-2015, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
/*
 * Creation : 5 mars 2015
 */
package org.seedstack.accounts.internal.domain.account;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import org.seedstack.business.domain.BaseAggregateRoot;
import org.seedstack.business.domain.Identity;

/**
 * An account is merely an id, a hashed password and the salt used to hash the
 * password.
 */
public class Account extends BaseAggregateRoot<String> implements Serializable {

    private static final long serialVersionUID = 4203266703741337332L;

    @Identity
    private String accountId;

    private String hashedPassword;

    private String salt;

    private Set<Role> roles;

    protected Account() {
    }

    Account(String id) {
        this.accountId = id;
        this.roles = new HashSet<Role>();
    }

    public String getEntityId() {
        return accountId;
    }

    /**
     * Returns the hashed password.
     *
     * @return a String being the hashed password
     */
    public String getHashedPassword() {
        return hashedPassword;
    }

    /**
     * Returns the salt used to hash the password.
     *
     * @return A String being the salt
     */
    public String getSalt() {
        return salt;
    }

    /**
     * Sets the hashed password.
     *
     * @param hashedPassword
     *            a String being the hashed password
     */
    public void setHashedPassword(String hashedPassword) {
        this.hashedPassword = hashedPassword;
    }

    /**
     * Sets the salt.
     *
     * @param salt
     *            a String being the salt
     */
    public void setSalt(String salt) {
        this.salt = salt;
    }

    /**
     * Returns the roles of this account.
     *
     * @return a Set of String, each String being a role. Empty list if none.
     */
    public Set<Role> getRoles() {
        return roles;
    }

    /**
     * Adds a new role.
     *
     * @param role
     *            name of the role
     */
    public void addRole(String role) {
        roles.add(new Role(role));
    }
}
