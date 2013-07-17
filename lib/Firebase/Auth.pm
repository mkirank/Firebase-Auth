package Firebase::Auth;

use strict;
use warnings;
use Carp 'croak';
use Digest::SHA qw(hmac_sha256);
use JSON::XS;
use POSIX;
use MIME::Base64;

our $VERSION = '0.02';

sub new {
    my $class = shift;
    my %opt=@_;

    if (! $opt{token} ) {
        croak "token is required";
    } 

    my $self = bless (\%opt, $class);

    $self->{TOKEN_VERSON} = 0;
    $self->{TOKEN_SEP} = '.';

    my %valid_opts = (
    'expires' => 'exp',
    'notBefore'=> 'nbf',
    'admin'=> 'admin',
    'debug'=> 'debug',
    'simulate'=> 'simulate'
    );
    $self->{valid_opts} = \%valid_opts;

    return $self;
}

sub create_token {
    my $self = shift;
    my $data = shift;
    my $options = shift;

    if ( ref($options) ne "HASH" ||  !$options ) {
        $options = {};
    }
    if ( ref($data) ne "HASH" ||  !$data) {
        $data = {};
    }

    my $claims = $self->_create_options_claims( $options );
    $claims->{v} = $self->{TOKEN_VERSON};
    my $t=time; 
    my $iat = mktime(localtime($t));
    $claims->{iat} = $iat;
    $claims->{d} = $data;

    return $self->_encode_token($claims)
}

sub _encode_token {
    my $self   = shift;
    my $claims = shift;

    my $ejsn = JSON::XS->new->utf8->space_after->encode ({'typ'=> 'JWT', 'alg'=> 'HS256'}) ;
    my $encoded_header = $self->urlbase64_encode( $ejsn);
    my $eclm = JSON::XS->new->utf8->space_after->encode ($claims);
    my $encoded_claims = $self->urlbase64_encode( $eclm );

    my $secure_bits = $encoded_header . $self->{TOKEN_SEP} . $encoded_claims;
    my $sig = $self->_sign($secure_bits);

    $secure_bits =
      $secure_bits . $self->{TOKEN_SEP} . $self->urlbase64_encode($sig);

    return $secure_bits;
}

sub urlbase64_encode {
    my $self = shift;
    my $data = shift;
    $data = encode_base64($data, '');
    $data =~ tr|+/=|\-_|d;
    return $data;
}
sub _sign {
    my $self = shift;
    my $bits = shift;
    my $digest=hmac_sha256($bits, $self->{token}); 
    return $digest;

}
sub _create_options_claims {
    my $self = shift;
    my $options = shift;
 
    my %valid_opts = %{$self->{valid_opts}};
    my $claims = {};

    foreach my $valid ( keys %{$options} ) {
        if ( exists $valid_opts{$valid} ) {
            $claims->{$valid_opts{$valid}} = $options->{$valid}
        } else {
            croak "Invalid option $valid";
        }
    }

    return $claims;
}
=head1 NAME

Firebase::Auth - The great new Firebase::Auth!

=head1 VERSION

Version 0.01

=cut



=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Firebase::Auth;

    my $foo = Firebase::Auth->new();
    ...

=head1 EXPORT

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 SUBROUTINES/METHODS

=head2 function1

=cut


=head2 function2

=cut


=head1 AUTHOR

 Kiran Kumar, C<< <kiran at brainturk.com> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-www-firebase at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=WWW-Firebase>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc WWW::Firebase


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=WWW-Firebase>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/WWW-Firebase>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/WWW-Firebase>

=item * Search CPAN

L<http://search.cpan.org/dist/WWW-Firebase/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2013  Kiran Kumar.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

1; # End of WWW::Firebase
