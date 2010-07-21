#!/usr/bin/perl
use strict;
use Net::DNS::Async;
use NetAddr::IP;

# rbllookup_async.pl - Thu Aug 20 13:13:35 EDT 2009
#
# Author: pblair(at)tucows(dot)com
# Updated: Thu Aug 20 13:14:14 EDT 2009
#
# This script takes input of bare IP addresses or addresses in CIDR notation
#
# Call like:
#
#   $ rbllookup_async.pl /file/containing/ips
#
# or
#
#   $ cat filename | rbllookup_async.pl -
#

my $c = new Net::DNS::Async( );
my $debug = 0;

my @zones = qw(
	b.barracudacentral.org
	bl.deadbeef.com
	bl.emailbasura.org
	bl.spamcannibal.org
	bl.spamcop.net
	blackholes.five-ten-sg.com
	blacklist.woody.ch
	bogons.cymru.com
	cbl.abuseat.org
	cdl.anti-spam.org.cn
	combined.rbl.msrbl.net
	db.wpbl.info
	dnsbl-1.uceprotect.net
	dnsbl-2.uceprotect.net
	dnsbl-3.uceprotect.net
	dnsbl.ahbl.org
	dnsbl.cyberlogic.net
	dnsbl.inps.de
	dnsbl.njabl.org
	dnsbl.sorbs.net
	drone.abuse.ch
	drone.abuse.ch
	duinv.aupads.org
	dul.dnsbl.sorbs.net
	dul.ru
	dyna.spamrats.com
	dynip.rothen.com
	fl.chickenboner.biz
	http.dnsbl.sorbs.net
	images.rbl.msrbl.net
	ips.backscatterer.org
	ix.dnsbl.manitu.net
	misc.dnsbl.sorbs.net
	noptr.spamrats.com
	ohps.dnsbl.net.au
	omrs.dnsbl.net.au
	orvedb.aupads.org
	osps.dnsbl.net.au
	osrs.dnsbl.net.au
	owfs.dnsbl.net.au
	owps.dnsbl.net.au
	phishing.rbl.msrbl.net
	probes.dnsbl.net.au
	proxy.bl.gweep.ca
	proxy.block.transip.nl
	psbl.surriel.com
	rbl.interserver.net
	rdts.dnsbl.net.au
	relays.bl.gweep.ca
	relays.bl.kundenserver.de
	relays.nether.net
	residential.block.transip.nl
	ricn.dnsbl.net.au
	rmst.dnsbl.net.au
	sbl.spamhaus.org
	short.rbl.jp
	smtp.dnsbl.sorbs.net
	socks.dnsbl.sorbs.net
	spam.abuse.ch
	spam.dnsbl.sorbs.net
	spam.rbl.msrbl.net
	spam.spamrats.com
	spamlist.or.kr
	spamrbl.imp.ch
	t3direct.dnsbl.net.au
	tor.ahbl.org
	tor.dnsbl.sectoor.de
	torserver.tor.dnsbl.sectoor.de
	ubl.lashback.com
	ubl.unsubscore.com
	virbl.bit.nl
	virus.rbl.jp
	virus.rbl.msrbl.net
	web.dnsbl.sorbs.net
	wormrbl.imp.ch
	zen.spamhaus.org
	zombie.dnsbl.sorbs.net
);

sub callback_a {
        my $response = shift || return;
	
	my $count = scalar @{$response->{answer}};
	return if $count == 0;

        return unless defined $response->{answer};
        for my $a ( @{$response->{answer}} ){

                # just get the address
                next unless defined $a->{address};

		# Get the IP that we're looking up
		my $ip = join( ".", reverse( split( /\./, $1 ) ) ) if $response->{question}->[0]->{qname} =~ /(\d+\.\d+\.\d+\.\d+?)\./;
		print "$ip,$a->{name},$a->{address}\n";
        }
}

sub lookup( $ ){
	my $ip = shift;

	for my $z ( sort( @zones ) ){
		my @q;
		my $iplookup = join( ".", reverse( split( /\./, $ip ) ) ) . "." . $z;
		push( @q, $iplookup );
		push( @q, 'A' );
		$c->add( { Callback => \&callback_a }, @q);
	}
}

while(<>){
	chomp;
	my @cidr;
	if( /((?:\d+\.){3}(?:\d+)\/\d+)/ ){
		my $n = NetAddr::IP->new( $_ );
		for my $ip ( @{$n->hostenumref} ){
			$ip =~ s/(\S+?)\/\d+/$1/;
			lookup( $ip );
		}
	}
	else {
		lookup( $_ );
	}
}

$c->await();
