#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More tests => 3;

BEGIN {
    use_ok( 'Firebase::Auth' ) || print "Bail out!\n";
}

diag( "Testing Firebase::Auth $Firebase::Auth::VERSION, Perl $], $^X" );

my $firebase= Firebase::Auth->new ( token =>'aca98axPOec');
isa_ok($firebase, 'Firebase::Auth');

eval {
    Firebase::Auth->new;
    };
    like($@, qr/token is required /, 'token is required :');


