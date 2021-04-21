package main

import (
	"fmt"
	"os"

	"github.com/nmcclain/ldap"
)

var (
	// LDAPServer is the hostname or IP Address of the LDAP Server to use for authentication
	LDAPServer = os.Getenv("LDAPSERVER")

	// LDAPPort is the number of the port of the LDAP Server to use for authentication
	LDAPPort = os.Getenv("LDAPPORT")
)

// AuthenticateLDAP authenticates a user (and password) against an LDAP Server
func AuthenticateLDAP(username, password string) (bool, error) {
	ldapServer := LDAPServer
	ldapPort := LDAPPort
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%s", ldapServer, ldapPort))
	if err != nil {
		return false, err
	}
	defer l.Close()
	err = l.Bind(username, password)
	return err == nil, err
}
