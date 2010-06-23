#!/usr/bin/perl
use strict;
use lib( "./" );
use ReturnPath::ISP::FBL;
use Data::Dumper;
use Getopt::Long;

# Command line options
my $search_pattern;
my $search_field;
my $debug = 0;
my $print_field;

my $result = GetOptions (
                        "searchpattern=s"   => \$search_pattern,      # string
			"searchfield=s"     => \$search_field,
			"printfield=s"      => \$print_field,
			"debug"  	    => \$debug,		      # flag
			); 



RECORD:for( @ARGV ){
	my $filename = $_ || die ("No file given\n");
	my $fbl = ReturnPath::ISP::FBL->new( $filename );

	my $cidr = $fbl->getcidr;

	# Search this against the searchpatterns
	PATTERN: for(1..1) { 
		# We want to evaluate all of the places where this
		# could reside, and search it. If no matches, then
		# go to next record
		if( defined $fbl->{contact}->{"$search_field"} ){
			last PATTERN if ( $fbl->{contact}->{"$search_field"} =~ /$search_pattern/oi ); 
		}
		if( defined $fbl->{fblinfo}->{"$search_field"} ){
			last PATTERN if ( $fbl->{fblinfo}->{"$search_field"} =~ /$search_pattern/oi ); 
		}

		if( $search_field eq 'filename' ){
			last PATTERN if ( $fbl->{filename} =~ /$search_pattern/oi );
		}	
		next RECORD;	# Nothing found...
	} 

	print Dumper( $fbl ) . "\n"
		if $debug;

	if( $print_field eq 'cidr' ){
		print join( "\n", @$cidr ) . "\n"
			if scalar @$cidr > 0;
	}
	elsif( $print_field eq 'filename' ){
		print $fbl->{filename} . "\n";
	}
	else {
		for my $section ( qw/ contact fblinfo / ){
			if( defined $fbl->{$section}->{"$print_field"} ){
				print $fbl->{$section}->{"$print_field"} . "\n";
			}
		}
	}
}

exit( 0 );
