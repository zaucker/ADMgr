# ADMgr
Active Directory Manager - Perl script using Net::LDAP to manage Active Directory users and groups

Usage:
```
./adMgr.pl: --adServer=hostname[:port] --adUser=adminUser --adPassword=password --adDomain=adDomain [params] action name

action: help|createUser|deleteUser|showUser|updateUser|showGroup|syncPasswd
params: for actions createUser (mandatory) and updateUser (optional)
          --firstname
          --lastname
          --password   (optional for createUser)
          --shell      Login shell
          --home       Unix home directory
          --uid        Unix user id
          --gid        Unix group id
          --verbose    Show user info after action
          --addToGroup AD group (always optional)

        for action syncPasswd
          --userPasswd  File in users' HOME with cleartext password
          --minUid      ignore uids below
          --maxUid      ignore uids above
          --delete      delete and recreate user accounts

          Lines with invalid gecos field (firstname lastname[,ORG]) and lines with shell=/bin/false are skipped.

         name:   username or groupname or passwdFilename (assumed to be in UTF-8)

```
