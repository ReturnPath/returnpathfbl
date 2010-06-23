package ReturnPath::ISP::FBL;
#
# This is a little package to parse in the accepted IP addresses
# from a returnpath FBL notifiation.  It can be used to feed
# into an RBL lookup, to determine if a given FBL should be
# NIXed or not.
#
# Author:
#
#	Peter Blair / pblair (AT) tucows (DOT) com
#
use strict;
use Data::Dumper;
use Email::Simple;

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
        new
	getcidr
);
$VERSION = '0.01';

sub new {
        my $class = shift;
        my $self = {
                filename     => shift
        };

        bless ($self, $class);

	# Open up the email
	my $emailstr = do { open FD, "<$self->{filename}" or die("$self->{filename}: $!\n"); local $/; <FD>; };

	my $email = Email::Simple->new( $emailstr );

	my $body = $email->body;


	# Get the IPs approved:
	my $ips_txt = $1 if ($body =~ /.*IPs approved:(.+)IPs declined:.*/gsm );
	my @ips = $ips_txt =~ /(\d+\.\d+\.\d+\.\d+)/g;
	$self->{ips} = \@ips;

	# Get the CIDR Ranges approved:
	my $cidr_txt = $1 if ($body =~ /.*CIDR ranges approved:(.+)CIDR ranges declined:.*/gsm );
	my @cidr = $cidr_txt =~ /(\d+\.\d+\.\d+\.\d+\/\d+)/g;
	$self->{cidr} = \@cidr;

	$self->{contact}->{firstname} = $1 if ( $body =~ /First Name:\s*(.*)/ );
	$self->{contact}->{lastname}  = $1 if ( $body =~ /Last Name:\s*(.*)/ );
	$self->{contact}->{company}  = $1 if ( $body =~ /Company:\s*(.*)/ );
	$self->{contact}->{phone}  = $1 if ( $body =~ /Phone:\s*(.*)/ );
	$self->{contact}->{email}  = $1 if ( $body =~ /Email:\s*(.*)/ );
	$self->{fblinfo}->{domain}  = $1 if ( $body =~ /Domain:\s*(.*)/ );
	$self->{fblinfo}->{fblemail}  = $1 if ( $body =~ /Feedback Loop Email:\s*(.*)/ );

	return $self;
}

# return an array ref of cidr addresses
sub getcidr {
	my ($self) = @_;
	my $cidr = [];
	for( @{$self->{ips}} ){
		my $t = $_ . "/32";
		push( @$cidr, $t );
	}

	for( @{$self->{cidr}} ){
		push( @$cidr, $_ );
	}
	return $cidr;
}

1;
__END__
