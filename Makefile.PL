use 5.006;
use strict;
use warnings FATAL => 'all';
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Firebase::Auth',
    AUTHOR           => q{ Kiran Kumar <kiran@brainturk.com>},
    VERSION_FROM     => 'lib/Firebase/Auth.pm',
    ABSTRACT_FROM    => 'lib/Firebase/Auth.pm',
    LICENSE          => 'Artistic_2_0',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
        'JSON::XS' =>0,
        'Carp' => 0,
        'Digest::SHA' => 0,
        'JSON::XS' => 0,
        'POSIX'   => 0,
        'MIME::Base64'  => 0,
    },
    PREREQ_PM => {
        #'ABC'              => 1.6,
        #'Foo::Bar::Module' => 5.0401,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Firebase-Auth-*' },
);
