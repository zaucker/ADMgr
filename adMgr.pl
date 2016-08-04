#! /usr/bin/env perl

use strict;
use warnings;
use v5.10; # we use features say and state

use lib "$ENV{HOME}/lib/perl-5.18.2";

use English qw( -no_match_vars );
use Getopt::Long;
use JSON;


#say encode_json \%defaults;

### ELKB tests
#
# ldapsearch -x -h eva.lkst.local -D "LKST\\Administrator" -W -b "cn=users,dc=lkst,dc=win" -s sub "(cn=*)" cn mail sn
# ldapsearch -x -LLL -E pr=200/noprompt -h eva.lkst.local -D "LKST\\Administrator" -W -b "cn=schema,cn=configuration,dc=lkst,dc=win" -s base

### ELKB local examples:
# ./adMgr.pl --adServer=eva.lkst.local:63636 --adUser=Administrator --adPassword=XXX --adDomain=lkst.win showUser zaucker

### ELKB from O+P (ssh tunnel) examples:
#
# adMgr.pl --adServer=localhost:63636 --adUser=Administrator --adPassword=XXX --adDomain=lkst.win syncPasswd adamPasswd --minUid=1000 --maxUid=1000 --userPasswd=rdpasswd
# ./adMgr.pl --adServer=localhost:63636 --adUser=Administrator --adPassword=XXX --adDomain=lkst.win showUser zaucker


sub usage; # defined below

my $defaults;

sub main {

    my ($verbose, $firstname, $lastname, $password,
        $shell, $uid, $gid, $home,
        $adDomain, $adServer, $adUser, $adPassword,
        $userPasswdFile, $minUid, $maxUid, $addToGroup, $delete
       );

    GetOptions (
        "firstname=s"  => \$firstname,
        "lastname=s"   => \$lastname,
        "password=s"   => \$password,
        "shell=s"      => \$shell,
        "home=s"       => \$home,
        "uid=i"        => \$uid,
        "gid=i"        => \$gid,
        "adServer=s"   => \$adServer,
        "adDomain=s"   => \$adDomain,
        "adUser=s"     => \$adUser,
        "adPassword=s" => \$adPassword,
        "userPasswd=s" => \$userPasswdFile,
        "minUid=i"     => \$minUid,
        "maxUid=i"     => \$maxUid,
        "delete"       => \$delete,
        "verbose"      => \$verbose,
        "addToGroup=s" => \$addToGroup,
    ) or die("Error in command line arguments\n");

    my $action = $ARGV[0] // 'help';
    my $name   = $ARGV[1] // '';

    usage if $action eq 'help';
    if (not $name and not $action =~ /showUser|syncPasswd/) {
        die "$action needs a user- or groupname";
    }

    my $defaultsFile = "$ENV{HOME}/.adMgrrc";
    if (-r $defaultsFile) {
        open my $fh, '<', $defaultsFile or die "Couldn't open $defaultsFile";
        local $/ = undef;
        my $data = <$fh>;
        close $fh;
        my $json = JSON->new;
        $json->relaxed([1]);
        $defaults = $json->decode($data);
    }


    $adServer       = $adServer       // $defaults->{adServer};
    $adDomain       = $adDomain       // $defaults->{adDomain};
    $adUser         = $adUser         // $defaults->{adUser};
    $shell          = $shell          // $defaults->{shell};
    $userPasswdFile = $userPasswdFile // $defaults->{userPasswd};
    $addToGroup     = $addToGroup     // $defaults->{addToGroup};

    usage unless $adServer and $adUser and $adPassword and $adDomain;

    my $ad = AdMgr->new(
        $adServer,
        $adDomain,
        $adUser,
        $adPassword,
        $verbose,
        { # Net::LDAPS options
         scheme => 'ldaps',
         debug  => 0,
        }
    );

    if ($action eq 'showUser') {
        $ad->showUsers($name);
    }
    elsif ($action eq 'showGroup') {
        my $users = $ad->getGroupMembers($name);
        if (@$users) {
            my @usernames;
            for my $u (@$users) {
                push @usernames, $u->get_value('sAMAccountName');
            }
            for my $u (sort @usernames) {
                say $u;
            }
        }
        else {
            say "No members found in $name";
        }
    }
    elsif ($action eq 'updateUser') {
        my %params;
        $params{firstname} = $firstname if $firstname;
        $params{lastname}  = $lastname  if $lastname;
        $params{password}  = $password  if $password;
        $params{shell}     = $shell     if $shell;
        $params{uid}       = $uid       if $uid;
        $params{gid}       = $gid       if $gid;
        $ad->updateUser($name, \%params);
        $ad->getUsers($name, [keys %params])->[0]->dump if $verbose;
        $ad->addToGroup($name, $addToGroup) if $addToGroup;
    }
    elsif ($action eq 'createUser') {
        my $oldUser = $ad->getUsers($name)->[0];
        die "User $name already exists" if $oldUser;
        my %params = (
            firstname => $firstname,
            lastname  => $lastname,
            password  => $password,
            shell     => $shell,
            uid       => $uid,
            gid       => $gid,
            home      => $home,
        );
        $ad->createUser($name, \%params);
        $ad->getUsers($name, [keys %params])->[0]->dump if $verbose;
        $ad->addToGroup($name, $addToGroup) if $addToGroup;
    }
    elsif ($action eq 'deleteUser') {
        my $oldUser = $ad->getUsers($name)->[0];
        die "User $name doesn't exists" unless $oldUser;
        $ad->deleteUser($name);
    }
    elsif ($action eq 'syncPasswd') {
        die "Cannot read passwd file $name" unless -r $name;
        $ad->syncPasswd($name, $userPasswdFile, $minUid, $maxUid, $delete, $addToGroup);
    }
    else {
        die "Unknown action $action";
    }

    $ad->unbind;   # take down session
    exit;
}

sub usage {
    die << "USAGE";
  Usage: $PROGRAM_NAME: --adServer=hostname[:port] --adUser=adminUser --adPassword=password --adDomain=adDomain [params] action name
         action: createUser|deleteUser|showUser|updateUser|showGroup|syncPasswd
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

                   Lines with invalid gecos field (firstname lastname[,ORG]) are skipped.
                   Lines with shell=/bin/false are skipped.

         name:   username or groupname or passwdFilename (assumed to be in UTF-8)

         Defaults: --adServer=$defaults->{adServer}
                   --adDomain=$defaults->{adDomain}
                   --adUser=$defaults->{adUser}
                   --shell=$defaults->{shell}
                   --userPasswd=$defaults->{userPasswd}
                   --addToGroup=$defaults->{addToGroup}
USAGE
}

main();
exit 0;


package AdMgr;

use Encode qw(encode);
use Net::LDAPS;
use Net::LDAP::Util qw(ldap_error_text ldap_error_name ldap_error_desc);

sub new {
    my $class  = shift;
    my $server = shift;
    my $domain = shift;
    my $adUser = shift;
    my $adPassword = shift;
    my $verbose    = shift;
    my $options    = shift;

    my @ldapOptions = %$options;

    my $ldap = Net::LDAPS->new(
                    $server,
                    # default options
                    scheme => 'ldaps',
                    debug  => 0,
                    # specific options
                    @ldapOptions,
               );

    my $self = bless {
        ldap    => $ldap,
        domain  => $domain,
        verbose => $verbose,
    }, $class;

    my $dc = $self->_getDc($domain);
    my $mesg = $ldap->bind(
        "cn=$adUser,cn=users,$dc",
        password => $adPassword
    );
    die "ERROR: " . $mesg->error if $mesg->code;

    return $self;
}

### accessors

sub ldap {
    return shift->{ldap};
}

sub domain {
    return shift->{domain};
}

sub verbose {
    return shift->{verbose};
}

### public methods

# ldapsearch -x -h eva.lkst.win -D lkst\\Administrator -W -b "cn=users,dc=lkst,dc=win" -s sub "(cn=*)" cn mail sn
sub getUsers {
    my $self = shift;

    my $ldap = $self->ldap;
    my $username = shift;
    my $attributes = shift // [];
    # $attributes = [ qw(cn uidNumber gidNumber homeDirectory loginShell sn) ];

#    my ($username, $domain) = split '@', $user;

    my $dc = $self->_getDc($self->domain);

    my $mesg = $ldap->search( # perform a search
        base   => "cn=users,$dc",
        # filter => "(&(sn=fritz))"
        # filter => 'sn=Zaucker',
        filter => 'sAMAccountName=' . ($username || '*'),
        attrs => $attributes
    );

    die $mesg->error if $mesg->code;

    my @users = $mesg->entries;
    return \@users;
}

sub showUsers {
    my $self     = shift;
    my $username = shift;

    my $users = $self->getUsers($username);
    if (@$users) {
        for my $u (@$users) {
            if ($self->verbose) {
                $u->dump;
            }
            else {
                my ($lastname, $firstname) = split / /, $u->get_value('displayName');
                my $fullname = "$firstname $lastname";
                say join ':', (
                        $u->get_value('sAMAccountName'),
                        'x',
                        $u->get_value('uidNumber'),
                        $u->get_value('gidNumber'),
                        $fullname,
                        $u->get_value('unixHomeDirectory'),
                        $u->get_value('loginShell'),
                    );
            }
        }
    }
    else {
        if ($username) {
            say "User $username not found";
        }
        else {
            say "No users found";
        }
    }
}

sub getGroupMembers {
    my $self      = shift;
    my $groupname = shift;

    my $ldap     = $self->ldap;
    my $adDomain = $self->domain;

    my $groupDN = $self->_getGroup($groupname)->dn;

    my $mesg = $ldap->search(
           base => $groupDN,
	       scope => 'base',
	       filter => "objectclass=*",
	       attrs => [ qw(member) ],
    );
    die $mesg->error if $mesg->code;

    my $group   = $mesg->entry;
    my @members = $group->get_value('member');
    my @users;
    for my $m (@members) {
        my $mesg =  $ldap->search(
            base => $m,
	        scope => 'base',
	        filter => "objectclass=*",
#	        attrs => [ qw(member) ],
        );
        die $mesg->error if $mesg->code;
        my $user = $mesg->entry;
        push @users, $user;
    }
    return \@users;
}

sub updateUser {
    my $self     = shift;
    my $username = shift;
    my $params   = shift;

    die "No user specified" unless $username;
    my $domainUser = $self->_makeDomainUser($username);
    my $ldap   = $self->ldap;

    my $unicodePwd = $self->_makePassword($params->{password}) if $params->{password};
    my $displayName = "$params->{lastname} $params->{firstname}"
                                 if $params->{firstname} and $params->{lastname};
    my %adParams;
    $adParams{givenName}         = $params->{firstname} if $params->{firstname};
    $adParams{sn}                = $params->{lastname}  if $params->{lastname};
    $adParams{uidNumber}         = $params->{uid}       if $params->{uid};
    $adParams{gidNumber}         = $params->{gid}       if $params->{gid};
    $adParams{loginShell}        = $params->{shell}     if $params->{shell};
    $adParams{unixHomeDirectory} = $params->{home}      if $params->{home};
    $adParams{unicodePwd}        = $unicodePwd          if $unicodePwd;
    $adParams{displayName}       = $displayName         if $displayName;

    if (scalar keys %adParams) {
        my $adUser = $self->getUsers($username)->[0];
        my $result = $ldap->modify($adUser, replace => \%adParams);
        $result->code && warn "Could not modify entry: " . ldap_error_name($result);
    }
}

sub addToGroup {
    my $self      = shift;
    my $username  = shift;
    my $groupname = shift;

    my $adDomain = $self->domain;
    my $ldap     = $self->ldap;

    my $group = $self->_getGroup($groupname);

    if ($self->_isGroupMember($username, $groupname)) {
        say "$username is already member of $groupname" if $self->verbose;
        return;
    }
    my $user       = shift $self->getUsers($username);
    my $fullname   = $user->get_value('distinguishedName');
    my $mesg = $ldap->modify(
        $group,
        add => {member => $fullname}
    );
    die $mesg->error if $mesg->code;
}

sub createUser {
    my $self     = shift;
    my $username = shift;
    my $params   = shift;

    my $ldap   = $self->ldap;

    die "No user specified" unless $username;
    my $required = [ qw(firstname lastname shell uid gid home) ];
    $self->_assertParams($params, $required);

    my $firstname = $params->{firstname};
    my $lastname  = $params->{lastname};
    my $password  = $params->{password};
    my $shell     = $params->{shell};
    my $uid       = $params->{uid};
    my $gid       = $params->{gid};
    my $home      = $params->{home};

    my $domainUser = $self->_makeDomainUser($username);
    my $adUser = $self->_makeAdUser("$firstname $lastname");
    my $attributes = [
        sAMAccountName     => $username,
        givenName          => $firstname,
        sn                 => $lastname,
        displayName        => "$lastname $firstname",
        userPrincipalName  => $domainUser,
        uidNumber          => $uid,
        gidNumber          => $gid,
        loginShell         => $shell,
        unixHomeDirectory  => $home,
        # AccountDisabled   => 0, # not disabled
        # PasswordRequired  => 1, # yes a password is required
        objectclass => [
            qw(top person organizationalPerson user)
            # 'inetOrgPerson'
        ],
    ];
    # http://rajnishbhatia19.blogspot.ch/2008/11/active-directory-useraccountcontrol.html
    if ($password) {
        push @$attributes, (
            unicodePwd         => $self->_makePassword($password),
            userAccountControl => 66048 # enabled, password doesn't expire
        );
    }
    else {
        push @$attributes, (
            userAccountControl => 65568, # enabled, doesn't expire, must change password
        );
    }
    my $result = $ldap->add(
        $adUser,
        attrs => $attributes
    );

    $result->code && warn "Failed to add entry: ", $result->error ;
    return $result;
}

sub deleteUser {
    my $self     = shift;
    my $username = shift;

    my $ldap = $self->ldap;

    die "No user specified" unless $username;

    my $adUser = $self->getUsers($username)->[0];

    my $result = $ldap->delete($adUser);
    $result->code && warn "Could not modify entry: " . ldap_error_name($result);
}

sub syncPasswd {
    my $self           = shift;
    my $passwdFile     = shift;
    my $userPasswdFile = shift;
    my $minUid         = shift // 0;
    my $maxUid         = shift // 100000;
    my $delete         = shift // 0;
    my $addToGroup     = shift;

    my $ldap     = $self->ldap;
    my $adDomain = $self->domain;

    open(my $fh, "<", $passwdFile)
        or die "Can't open passwdFile $passwdFile: $!";
    my $updates = 0;
    my $creates = 0;
    my $skips   = 0;
    my $updateAction = $delete ? "delete" : "update";
    while (<$fh>) {
        my $line = $_;
        chomp $line;
        my ($username, $x, $uid, $gid, $gecos, $home, $shell) = split ':', $line;
        next if $shell eq '/bin/false';
        next if $uid < $minUid or $uid > $maxUid;
        my $fullname = $gecos;
        if ($gecos =~ m/,/) {
            my $dummy;
            ($fullname, $dummy) = split ',', $gecos;
        }
        my ($firstname, $lastname) = split ' ', $fullname;
        if (not $lastname or $shell eq '/bin/false') {
            say "Skipping $username";
            $skips++;
            next;
        }
        my $password;
        my $rdpasswordFile = "$home/$userPasswdFile" if $userPasswdFile;
        if (defined $rdpasswordFile and -r $rdpasswordFile) {
            open (my $pwFh, "<", $rdpasswordFile) or die "Couldn't open $rdpasswordFile";
            $password = <$pwFh>;
            chomp $password;
            close $pwFh;
        }
        my %params = (
            firstname => $firstname,
            lastname  => $lastname,
            shell     => $shell,
            uid       => $uid,
            gid       => $gid,
            home      => $home,
        );
        $params{password} = $password if $password;

#        my $domainUser = "$username\@$adDomain";
        if ( $self->getUsers($username)->[0] ) {
            say ucfirst "$updateAction $username";
            $delete ? $self->deleteUser($username)
                    : $self->updateUser($username, \%params);
            $updates++;
        }
        else {
            say "Create $username: $firstname $lastname";
            $self->createUser($username, \%params);
            $creates++;
        }
        $self->addToGroup($username, $addToGroup) if $addToGroup;
    }
    close $fh;
    say "$creates accounts created, $updates ${updateAction}d, $skips skipped.";
}

sub unbind {
    my $self = shift;

    my $mesg = $self->ldap->unbind;
    die $mesg->error if $mesg->code;
}

### helper methods

sub _getDc {
    my $self   = shift;
    my $domain = shift;

    return join ',', map { "dc=$_" } split '\.', $domain;
}

sub _getGroup {
    my $self      = shift;
    my $groupname = shift;

    my $ldap     = $self->ldap;
    my $adDomain = $self->domain;

    my $dc   = $self->_getDc($adDomain);
    my $mesg = $ldap->search( # perform a search
        base   => "cn=$groupname,$dc",
        filter => "(&(member=*))",
        attrs => [ qw(dn) ]
    );
    die $mesg->error if $mesg->code;

    my $group = $mesg->entry;
    return $group;
}

sub _makeDomainUser {
    my $self = shift;
    my $name = shift;

    return $name . '@' . $self->domain;
}

sub _assertParams {
    my $self         = shift;
    my $params       = shift;
    my $keysRequired = shift;

    my $errors = 0;
    for my $k (@$keysRequired) {
        $errors++ => say "Missing parameter: $k" unless $params->{$k};
    }
    die "$errors missing parameters found" if $errors;
}

sub _makeAdUser {
    my $self     = shift;
#    my $username = shift;
    my $fullname = shift;

#    my ($username, $domain) = split '@', $user;
    my $domain = $self->domain;

    my $cn = "cn=$fullname,cn=users";
    my $dc = join ',', map { "dc=$_" } split '\.', $domain;

    return "$cn,$dc";
}

sub _makePassword {
    my $self     = shift;
    my $password = shift;

    return encode('UTF-16LE', chr(34) . $password . chr(34));
}

{   # cache groupMembers for syncPasswd
    my %groupMembers;

    sub _isGroupMember {
        my $self = shift;
        my $username  = shift;
        my $groupname = shift;

        my $ldap      = $self->ldap;
        my $adDomain  = $self->domain;

        if (not scalar keys %groupMembers) {
            my $members = $self->getGroupMembers($groupname);
            for my $m (@$members) {
                $groupMembers{$m->get_value('sAMAccountName')} = 1;
            }
        }
        return exists $groupMembers{$username};
    }
}

1;

### various docs
#
# http://www.barncrew.com/changing-an-active-directory-password-from-perl/
# http://ldapwiki.willeke.com/wiki/Perl%20Add%20User%20Sample
# http://stackoverflow.com/questions/20846597/using-perl-to-get-users-of-ad-group
# http://www.developer.com/open/article.php/10930_3106601_3/Searching-Active-Directory-with-Perl.htm
# http://grokbase.com/t/perl/ldap/069wqmq9m0/adding-groups-to-a-user-account
# http://blogthing.eskibars.com/project/populating-users-in-active-directory-using-perl-with-ole/
# https://blog.varonis.com/how-to-find-active-directory-group-member/
# https://blog.varonis.com/how-to-find-active-directory-group-member/
# http://www.vinidox.com/ldap/querying-an-ldap-server-from-the-command-line-with-ldap-utils-ldapsearch-ldapadd-ldapmodify
# http://www.itadmintools.com/2010/09/accessing-active-directory-using-perl.html
# http://www.itadmintools.com/2010/09/accessing-active-directory-using-perl.html



__END__

=head1 NAME

aduser.pl - Active Directory user manager

=head1 SYNOPSIS

B<aduser.pl help> for usage instructions

=head1 DESCRIPTION

Create, delete, update Active Directory user accounts.

Sync with Unix /etc/passwd file


=head1 COPYRIGHT

Copyright (c) 2016- by OETIKER+PARTNER AG. All rights reserved.

=head1 LICENSE

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

=head1 AUTHOR

S<Fritz Zaucker E<lt>fritz.zaucker@oetiker.chE<gt>>

=head1 HISTORY

 2016-07-21 za 1.0 first version

=cut

# Emacs Configuration
#
# Local Variables:
# mode: cperl
# eval: (cperl-set-style "PerlStyle")
# mode: flyspell
# mode: flyspell-prog
# End:
#
# vi: sw=4 et
