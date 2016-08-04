# ADMgr
Active Directory Manager - Perl script using Net::LDAPS to manage Active Directory users and groups

Usage:
```
./adMgr.pl: --adServer=host[:port] --adUser=user --adPassword=password --adDomain=domain [params] action name

adPassword will be prompted for if not given on commandline or defaults file.

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

Defaults can be stored in $HOME/.adMgrrc for:
    --adServer
    --adDomain
    --adUser
    --adPassword
    --shell
    --userPasswd
    --addToGroup
```
