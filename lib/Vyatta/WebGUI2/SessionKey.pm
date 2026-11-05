# Module: SessionKey.pm
# Description: used to generate session key 
#
# Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
# Copyright (c) 2009-2010 Vyatta, Inc.
# All Rights Reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only

use strict;
use warnings;

use Fcntl qw(:DEFAULT :flock :mode);
use File::Temp qw(tempfile);
use JSON;
use Time::HiRes qw(usleep);

my $session_dir = "/var/run/gui";
my $lck_file = "$session_dir/session.lck";
my $sess_file = "$session_dir/session";

sub gen_key
{
    my ($src_ip) = @_;
    exit(1) unless defined($src_ip);

    open(my $random, '<:raw', '/dev/urandom') or exit(1);
    my $bytes;
    my $count = read($random, $bytes, 8);
    exit(1) unless defined($count) && $count == 8;
    close($random) or exit(1);
    return uc(unpack('H*', $bytes));
}

sub _trusted_file
{
    my ($file) = @_;
    my @info = stat($file);
    return @info && S_ISREG($info[2]) && ($info[2] & 07777) == 0600 &&
        $info[3] == 1 && $info[4] == 0;
}

sub get_key
{
    my ($name, $access_level, $src_ip) = @_;
    exit(1) unless defined($name) && length($name) &&
        defined($src_ip) && length($src_ip) && defined($access_level);
    for my $field ($name, $access_level, $src_ip) {
        exit(1) if $field =~ /[,\r\n\0]/;
    }

    # /var/run resolves to root-owned /run. Check the final component before
    # touching files, and validate the open handles without following links.
    my @dir = lstat($session_dir);
    exit(1) unless $> == 0 && @dir && S_ISDIR($dir[2]) &&
        ($dir[2] & 07777) == 0700 && $dir[4] == 0;
    umask(0077);
    my $flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK;
    sysopen(my $lock, $lck_file, $flags | O_CREAT, 0600) or exit(1);
    exit(1) unless _trusted_file($lock);
    my $attempt = 0;
    until (flock($lock, LOCK_EX | LOCK_NB)) {
        exit(1) if ++$attempt == 5 || (!$!{EWOULDBLOCK} && !$!{EINTR});
        usleep(50_000);
    }

    my $session;
    if (sysopen($session, $sess_file, $flags)) {
        exit(1) unless _trusted_file($session);
    } else {
        exit(1) unless $!{ENOENT};
        undef $session;
    }

    my ($tmp, $tmp_path) = tempfile('session.XXXXXX', DIR => $session_dir, UNLINK => 1);
    exit(1) unless _trusted_file($tmp);
    my $now = time;
    my $key;
    if ($session) {
        while (1) {
            $! = 0;
            my $line = <$session>;
            if (!defined($line)) {
                exit(1) if $!;
                last;
            }
            my @fields = split(/,/, $line, -1);
            next unless @fields == 5 && length($line) < 1024 && $line =~ /\n\z/;
            my ($id, $user, $issued, $source) = @fields;
            next unless $issued =~ /\A[0-9]+\z/ &&
                $issued <= $now && $now - $issued < 30 * 60;
            if ($user eq $name && $source eq $src_ip) {
                $key //= $id if $id =~ /\A[0-9a-fA-F]{16}\z/;
            } else {
                print {$tmp} $line or exit(1);
            }
        }
        close($session) or exit(1);
    }
    $key //= gen_key($src_ip);
    my $record = "$key,$name,$now,$src_ip,$access_level\n";
    exit(1) if length($record) >= 1024;
    print {$tmp} $record or exit(1);
    close($tmp) or exit(1);
    rename($tmp_path, $sess_file) or exit(1);
    close($lock) or exit(1);

    print to_json({session => { user => $name, source => $src_ip, key => $key }},
                  {pretty => 1});
    exit(0);
}

1;
