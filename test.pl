#!/usr/bin/env perl 
use strict;
use warnings;
use feature ':5.12';

use WWW::Firebase;

my $tk="0014ae3b1ded44de9d9f6fc60dfd1c64";
my $firebase = WWW::Firebase->new ( token =>$tk);
my %custom_data = ("id" => "example");
my $token = $firebase->create_token ( \%custom_data );
 say( "token $token");
