#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More tests => 6;

BEGIN {
    use_ok( 'Firebase::Auth' ) || print "Bail out!\n";
}

my $tk = 'aca98axPOec';

my $firebase= Firebase::Auth->new ( token =>$tk);

isa_ok($firebase, 'Firebase::Auth');

is ($firebase->{token} , $tk, 'token added');

my $options = {
    expres =>'100',
};
eval {
    $firebase->_create_options_claims( $options );
};
like($@, qr/Invalid option expres/,'Invalid option');
my $claims;

$options = {
    expires =>'100',
};

eval {
    $claims = $firebase->_create_options_claims( $options );
};

is ($claims->{exp}, 100 , 'Claims returned correctly');

$options = { };

eval {
    $claims = $firebase->_create_options_claims( $options );
};

 is_deeply ($claims, {} , 'Empty hashref returned');

# my $custom_data = {'auth_data', 'foo', 'other_auth_data', 'bar'};
# $options = {'admin'=> 'True'};

# my $token = $firebase->create_token ( $custom_data, $options );
# diag ( "token $token");

