#!/usr/bin/env perl 
use strict;
use warnings;

use Firebase::Auth;

my $tk="AsdueloieTusMLS0cWFEgzmaW6xVDsXND3Vk6";
my $custom_data = {'auth_data' => 'foo', 'other_auth_data'=> 'bar'};
my $options = {'admin' => 'true'};

my $firebase = Firebase::Auth->new ( token =>$tk);
my $token = $firebase->create_token ( $custom_data, $options );
 print( "token $token \n");
