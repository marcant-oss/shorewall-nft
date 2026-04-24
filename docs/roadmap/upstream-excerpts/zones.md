# Zones.pm — extracted functions

**Source**: `Shorewall/Perl/Shorewall/Zones.pm`
**Git tag**: 5.2.6.1
**Purpose**: Reference for shorewall-nft Phase 6 work-package agents.

## Index

- `process_zone` (lines 547–675): zone definition row processor (incl. ipsec OPTIONS)
- `process_interface` (lines 1210–1589): interfaces file row processor (full OPTIONS list)
- `process_host` (lines 2143–2281): hosts file row processor (full OPTIONS list)

## process_zone (lines 547–675)

> zone definition row processor (incl. ipsec OPTIONS)

```perl
sub process_zone( \$ ) {
    my $ip = $_[0];

    my @parents;

    my ($zone, $type, $options, $in_options, $out_options ) =
	split_line( 'zones file',
		    { zone => 0, type => 1, options => 2, in_options => 3, out_options => 4 } );

    fatal_error 'ZONE must be specified' if $zone eq '-';

    if ( $zone =~ /(\w+):([\w,]+)/ ) {
	$zone = $1;
	@parents = split_list $2, 'zone';
    }

    fatal_error "Invalid zone name ($zone)"      unless $zone =~ /^[a-z]\w*$/i;
    fatal_error "Zone name ($zone) too long"     unless length $zone <= $globals{MAXZONENAMELENGTH};
    fatal_error "Invalid zone name ($zone)"      if $reservedName{$zone} || $zone =~ /^all2|2all$/;
    fatal_error( "Duplicate zone name ($zone)" ) if $zones{$zone};

    if ( $type =~ /^ip(v([46]))?$/i ) {
	fatal_error "Invalid zone type ($type)" if $1 && $2 != $family;
	$type = IP;
	$$ip = 1;
    } elsif ( $type =~ /^ipsec([46])?$/i ) {
	fatal_error "Invalid zone type ($type)" if $1 && $1 != $family;
	require_capability 'POLICY_MATCH' , 'IPSEC zones', '';
	$type = IPSEC;
    } elsif ( $type =~ /^bport([46])?$/i ) {
	fatal_error "Invalid zone type ($type)" if $1 && $1 != $family;
	warning_message "Bridge Port zones should have a parent zone" unless @parents || $config{ZONE_BITS};
	$type = BPORT;
	push @bport_zones, $zone;
    } elsif ( $type eq 'firewall' ) {
	fatal_error 'Firewall zone may not be nested' if @parents;
	fatal_error "Only one firewall zone may be defined ($zone)" if $firewall_zone;
	$firewall_zone = $zone;
	add_param( FW => $zone );
	$type = FIREWALL;
    } elsif ( $type eq 'vserver' ) {
	fatal_error 'Vserver zones may not be nested' if @parents;
	$type = VSERVER;
    } elsif ( $type eq '-' ) {
	$type = IP;
	$$ip = 1;
    } elsif ( $type eq 'local' ) {
	push @local_zones, $zone;
	$type = LOCAL;
	$$ip  = 1;
    } elsif ( $type eq 'loopback' ) {
	push @loopback_zones, $zone;
	$type = LOOPBACK;
    } else {
	fatal_error "Invalid zone type ($type)";
    }

    for my $p ( @parents ) {
	fatal_error "Invalid Parent List ($2)" unless $p;
	fatal_error "Unknown parent zone ($p)" unless $zones{$p};

	my $ptype = $zones{$p}{type};

	fatal_error 'Subzones of a Vserver zone not allowed' if $ptype & VSERVER;
	fatal_error 'Subzones of firewall zone not allowed'  if $ptype & FIREWALL;
	fatal_error 'Loopback zones may only be subzones of other loopback zones' if ( $type | $ptype ) & LOOPBACK && $type != $ptype;
	fatal_error 'Local zones may only be subzones of other local zones'       if ( $type | $ptype ) & LOCAL    && $type != $ptype;

	set_super( $zones{$p} ) if $type & IPSEC && ! ( $ptype & IPSEC );

	push @{$zones{$p}{children}}, $zone;
    }

    my $complex = 0;

    my $zoneref = $zones{$zone} = { name       => $zone,
				    type       => $type,
				    parents    => \@parents,
				    bridge     => '',
				    options    => { in_out  => parse_zone_option_list( $options , $type, $complex , IN_OUT ) ,
						    in      => parse_zone_option_list( $in_options , $type , $complex , IN ) ,
						    out     => parse_zone_option_list( $out_options , $type , $complex , OUT ) ,
						  } ,
				    super      => 0 ,
				    complex    => ( $type & IPSEC || $complex ) ,
				    interfaces => {} ,
				    children   => [] ,
				    hosts      => {}
				  };

    if ( $config{ZONE_BITS} ) {
	my $mark;

	if ( $type == FIREWALL ) {
	    $mark = 0;
	} else {
	    unless ( $zoneref->{options}{in_out}{nomark} ) {
		fatal_error "Zone mark overflow - please increase the setting of ZONE_BITS" if $zonemark >= $zonemarklimit;
		$mark      = $zonemark;
		$zonemark += $zonemarkincr;
		$zoneref->{complex} = 1;
	    }
	}

	if ( $zoneref->{options}{in_out}{nomark} ) {
	    progress_message_nocompress "   Zone $zone:\tmark value not assigned";
	} else {
	    progress_message_nocompress "   Zone $zone:\tmark value " . in_hex( $zoneref->{mark} = $mark );
	}
    }

    if ( $zoneref->{options}{in_out}{blacklist} ) {
	warning_message q(The 'blacklist' option is no longer supported);
	for ( qw/in out/ ) {
	    unless ( $zoneref->{options}{$_}{blacklist} ) {
		$zoneref->{options}{$_}{blacklist} = 1;
	    } else {
		warning_message( "Redundant 'blacklist' in " . uc( $_ ) . '_OPTIONS' );
	    }
	}
    } else {
	for ( qw/in out/ ) {
	    warning_message q(The 'blacklist' option is no longer supported), last if  $zoneref->{options}{$_}{blacklist};
	}
    }

    return $zone;

}
```

## process_interface (lines 1210–1589)

> interfaces file row processor (full OPTIONS list)

```perl
sub process_interface( $$ ) {
    my ( $nextinum, $export ) = @_;
    my $netsref   = '';
    my $filterref = [];
    my ($zone, $originalinterface, $bcasts, $options );
    my $zoneref;
    my $bridge = '';

    if ( $file_format == 1 ) {
	($zone, $originalinterface, $bcasts, $options ) =
	    split_line1( 'interfaces file',
			 { zone => 0, interface => 1, broadcast => 2, options => 3 } );
    } else {
	($zone, $originalinterface, $options ) = split_line1( 'interfaces file',
							      { zone => 0, interface => 1, options => 2 } );
	$bcasts = '-';
    }

    if ( $zone eq '-' ) {
	$zone = '';
    } else {
	$zoneref = $zones{$zone};

	fatal_error "Unknown zone ($zone)" unless $zoneref;
	fatal_error "Firewall zone not allowed in ZONE column of interface record" if $zoneref->{type} == FIREWALL;
    }

    fatal_error 'INTERFACE must be specified' if $originalinterface eq '-';

    my ($interface, $port, $extra) = split /:/ , $originalinterface, 3;

    fatal_error "Invalid interface name ($interface)" if $interface =~ /[()\[\]\*\?%]/;

    fatal_error "Invalid INTERFACE ($originalinterface)" if ! $interface || defined $extra;

    if ( supplied $port ) {
	fatal_error qq("Virtual" interfaces are not supported -- see https://shorewall.org/Shorewall_and_Aliased_Interfaces.html) if $port =~ /^\d+$/;
	require_capability( 'PHYSDEV_MATCH', 'Bridge Ports', '');
	fatal_error "Your iptables is not recent enough to support bridge ports" unless $globals{KLUDGEFREE};

	fatal_error "Invalid Interface Name ($interface:$port)" unless $port =~ /^[\w.@%-]+\+?$/;
	fatal_error "Duplicate Interface ($port)" if $interfaces{$port};

	fatal_error "$interface is not a defined bridge" unless $interfaces{$interface} && $interfaces{$interface}{options}{bridge};
	$interfaces{$interface}{ports}++;
	fatal_error "Bridge Ports may only be associated with 'bport' zones" if $zone && ! ( $zoneref->{type} & BPORT );

	if ( $zone ) {
	    if ( $zoneref->{bridge} ) {
		fatal_error "Bridge Port zones may only be associated with a single bridge" if $zoneref->{bridge} ne $interface;
	    } else {
		$zoneref->{bridge} = $interface;
	    }

	    fatal_error "Vserver zones may not be associated with bridge ports" if $zoneref->{type} & VSERVER;
	}

	$bridge = $interface;
	$interface = $port;
    } else {
	fatal_error "Duplicate Interface ($interface)" if $interfaces{$interface};
	fatal_error "Zones of type 'bport' may only be associated with bridge ports" if $zone && $zoneref->{type} & BPORT;
	fatal_error "Vserver zones may not be associated with interfaces" if $zone && $zoneref->{type} & VSERVER;

	$bridge = $interface;
    }

    my $wildcard = 0;
    my $physwild = 0;
    my $root;

    if ( $interface =~ /\+$/ ) {
	$wildcard = $physwild = 1; # Default physical name is the logical name
	$root = substr( $interface, 0, -1 );
	$roots{$root} = $interface;
	my $len = length $root;

	if ( defined $minroot ) {
	    $minroot = $len if $minroot > $len;
	} else {
	    $minroot = $len;
	}
    } else {
	$root = $interface;
    }

    fatal_error "Invalid interface name ($interface)" if $interface =~ /\*/;

    my $physical = $interface;
    my $broadcasts;

    unless ( $bcasts eq '-' || $bcasts eq 'detect' ) {
	my @broadcasts = split_list $bcasts, 'address';

	for my $address ( @broadcasts ) {
	    fatal_error 'Invalid BROADCAST address' unless $address =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
	}

	if ( have_capability( 'ADDRTYPE' ) ) {
	    warning_message 'Shorewall no longer uses broadcast addresses in rule generation when Address Type Match is available';
	} else {
	    $broadcasts = \@broadcasts;
	}
    }

    my %options;

    $options{port} = 1 if $port;
    $options{dbl}  = $config{DYNAMIC_BLACKLIST} =~ /^ipset(-only)?.*,src-dst/ ? '1:2' : $config{DYNAMIC_BLACKLIST} ? '1:0' : '0:0';

    my $hostoptionsref = {};

    if ( $options eq 'ignore' ) {
	fatal_error "Ignored interfaces may not be associated with a zone" if $zone;
	$options{ignore} = NO_UPDOWN | NO_SFILTER;
	$options = '-';
    }

    if ( $options ne '-' ) {

	my %hostoptions = ( dynamic => 0 );

	for my $option (split_list1 $options, 'option' ) {
	    ( $option, my $value ) = split /=/, $option;

	    fatal_error "Invalid Interface option ($option)" unless my $type = $validinterfaceoptions{$option};

	    my $hostopt = $type & IF_OPTION_HOST;

	    $type &= MASK_IF_OPTION;

	    unless ( $type == BINARY_IF_OPTION && defined $value && $value eq '0' ) {
		if ( $zone ) {
		    fatal_error qq(The "$option" option may not be specified for a Vserver zone") if $zoneref->{type} & VSERVER && ! ( $type & IF_OPTION_VSERVER );
		} else {
		    fatal_error "The \"$option\" option may not be specified on a multi-zone interface" if $type & IF_OPTION_ZONEONLY;
		}
	    }

	    fatal_error "The \"$option\" option is not allowed on a bridge port" if $port && ! $hostopt;

	    if ( $type == SIMPLE_IF_OPTION ) {
		fatal_error "Option $option does not take a value" if defined $value;
		if ( $option eq 'blacklist' ) {
		    warning_message "The 'blacklist' interface option is no longer supported";
		    if ( $zone ) {
			$zoneref->{options}{in}{blacklist} = 1;
		    } else {
			warning_message "The 'blacklist' option is ignored on multi-zone interfaces";
		    }
		} elsif ( $option eq 'nodbl' ) {
		    $options{dbl} = '0:0';
		} else {
		    $options{$option} = 1;
		    $hostoptions{$option} = 1 if $hostopt;
		}
	    } elsif ( $type == BINARY_IF_OPTION ) {
		$value = 1 unless defined $value;
		fatal_error "Option value for '$option' must be 0 or 1" unless ( $value eq '0' || $value eq '1' );
		$options{$option} = $value;
		$hostoptions{$option} = $value if $hostopt;
	    } elsif ( $type == ENUM_IF_OPTION ) {
		if ( $option eq 'arp_ignore' ) {
		    fatal_error q(The 'arp_ignore' option may not be used with a wild-card interface name) if $wildcard;
		    if ( defined $value ) {
			if ( $value =~ /^[1-3,8]$/ ) {
			    $options{arp_ignore} = $value;
			} else {
			    fatal_error "Invalid value ($value) for arp_ignore";
			}
		    } else {
			$options{arp_ignore} = 1;
		    }
		} elsif ( $option eq 'dbl' ) {
		    my %values = ( none => '0:0', src => '1:0', dst => '2:0', 'src-dst' => '1:2' );

		    fatal_error q(The 'dbl' option requires a value) unless defined $value;
		    fatal_error qq(Invalid setting ($value) for 'dbl') unless defined ( $options{dbl} = $values{$value} );
		} else {
		    assert( 0 );
		}
	    } elsif ( $type == NUMERIC_IF_OPTION ) {
		$value = $defaultinterfaceoptions{$option} unless defined $value;
		fatal_error "The '$option' option requires a value" unless defined $value;
		my $numval = numeric_value $value;
		fatal_error "Invalid value ($value) for option $option" unless defined $numval && $numval <= $maxoptionvalue{$option};
		require_capability 'TCPMSS_TARGET', "mss=$value", 's' if $option eq 'mss';
		$options{logmartians} = 1 if $option eq 'routefilter' && $numval && ! $config{LOG_MARTIANS};
		$options{$option} = $numval;
		$hostoptions{$option} = $numval if $hostopt;
	    } elsif ( $type == IPLIST_IF_OPTION ) {
		fatal_error "The '$option' option requires a value" unless defined $value;
		#
		# Add all IP to the front of a list if the list begins with '!'
		#
		$value = join ',' , ALLIP , $value if $value =~ /^!/;

		if ( $option eq 'nets' ) {
		    fatal_error q("nets=" may not be specified for a multi-zone interface) unless $zone;
		    fatal_error "Duplicate $option option" if $netsref;
		    if ( $value eq 'dynamic' ) {
			require_capability( 'IPSET_V5', 'Dynamic nets', '');
			$hostoptions{dynamic} = 1;
			#
			# Defer remaining processing until we have the final physical interface name
			#
			$netsref = 'dynamic';
		    } else {
			$hostoptions{multicast} = 1;
			#
			# Convert into a Perl array reference
			#
			$netsref = [ split_list $value, 'address' ];
		    }
		    #
		    # Assume 'broadcast'
		    #
		    $hostoptions{broadcast} = 1;
		} elsif ( $option eq 'sfilter' ) {
		    $filterref = [ split_list $value, 'address' ];
		    validate_net( $_, 0) for @{$filterref}
		} else {
		    assert(0);
		}
	    } elsif ( $type == STRING_IF_OPTION ) {
		fatal_error "The '$option' option requires a value" unless supplied $value;

		if ( $option eq 'physical' ) {
		    fatal_error "Invalid interface name ($interface)" if $interface =~ /[()\[\]\*\?%]/;
		    fatal_error "Virtual interfaces ($value) are not supported" if $value =~ /:\d+$/;

		    fatal_error "Duplicate physical interface name ($value)" if ( $interfaces{$value} && ! $port );

		    $physwild = ( $value =~ /\+$/ );
		    fatal_error "The type of 'physical' name ($value) doesn't match the type of interface name ($interface)" if $wildcard && ! $physwild;

		    $physical = $value;
		} else {
		    assert(0);
		}
	    } else {
		warning_message "Support for the $option interface option has been removed from Shorewall";
	    }
	}

	fatal_error q(The 'required', 'optional' and 'ignore' options are mutually exclusive)
	    if ( ( $options{required} && $options{optional} ) ||
		 ( $options{required} && $options{ignore}   ) ||
		 ( $options{optional} && $options{ignore}   ) );

	if ( $options{rpfilter} ) {
	    require_capability( 'RPFILTER_MATCH', q(The 'rpfilter' option), 's' ) ;
	    fatal_error q(The 'routefilter', 'sfilter' and 'rpfilter' options are mutually exclusive) if $options{routefilter} || @$filterref;
	} else {
	    fatal_error q(The 'routefilter', 'sfilter' and 'rpfilter' options are mutually exclusive) if $options{routefilter} && @$filterref;
	}

	if ( supplied( my $ignore = $options{ignore} ) ) {
	    fatal_error "Invalid value ignore=0" if ! $ignore;
	} else {
	    $options{ignore} = 0;
	}

	for my $option ( keys %options ) {
	    if ( $root ) {
		warning_message( "The '$option' option is ignored when used with a wildcard physical name" ) if $physwild && $procinterfaceoptions{$option};
	    } else {
		warning_message( "The '$option' option is ignored when used with interface name '+'" ) unless $validinterfaceoptions{$option} & IF_OPTION_WILDOK;
	    }
	}

	if ( $netsref eq 'dynamic' ) {
	    my $ipset = $family == F_IPV4 ? "${zone}" : "6_${zone}";
	    $ipset = join( '_', $ipset, var_base1( $physical ) ) unless $zoneref->{options}{in_out}{dynamic_shared};	    
	    $netsref = [ "+$ipset" ];
	    add_ipset($ipset);
	}

	if ( $options{bridge} ) {
	    require_capability( 'PHYSDEV_MATCH', 'The "bridge" option', 's');
	    fatal_error "Bridges may not have wildcard names" if $wildcard;
	    $hostoptions{routeback} = $options{routeback} = 1 unless supplied $options{routeback};
	}

	$hostoptions{routeback} = $options{routeback} = is_a_bridge( $physical ) unless $export || supplied $options{routeback} || $options{unmanaged};

	$hostoptionsref = \%hostoptions;
    } else {
	#
	# No options specified -- auto-detect bridge
	#
	$hostoptionsref->{routeback} = $options{routeback} = is_a_bridge( $physical ) unless $export;
	#
	# And give the 'ignore' option a defined value
	#
	$options{ignore} ||= 0;
    }

    $options{loopback} ||= ( $physical eq 'lo' );

    if ( $options{loopback} ) {
	fatal_error "Only one 'loopback' interface is allowed" if $loopback_interface;
	$loopback_interface = $physical;
    }

    if ( $options{unmanaged} ) {
	fatal_error "The loopback interface ($loopback_interface) may not be unmanaged when there are vserver zones" if $options{loopback} && vserver_zones;

	while ( my ( $option, $value ) = each( %options ) ) {
	    fatal_error "The $option option may not be specified with 'unmanaged'" if $prohibitunmanaged{$option};
	}
    } else {
	$options{tcpflags} = $hostoptionsref->{tcpflags} = 1 unless exists $options{tcpflags};
    }

    my $interfaceref = $interfaces{$interface} = { name       => $interface ,
						   bridge     => $bridge ,
						   filter     => $filterref ,
						   nets       => 0 ,
						   number     => $nextinum ,
						   root       => $root ,
						   broadcasts => $broadcasts ,
						   options    => \%options ,
						   zone       => '',
						   physical   => $physical ,
						   base       => var_base( $physical ),
						   zones      => {},
						   origin     => shortlineinfo( '' ),
						   wildcard   => $wildcard,
						   physwild   => $physwild, # Currently unused
					         };

    $interfaces{$physical} = $interfaceref if $physical ne $interface;

    if ( $zone ) {
	fatal_error "Unmanaged interfaces may not be associated with a zone" if $options{unmanaged};

	if ( $options{loopback} ) {
	    fatal_error "Only a loopback zone may be assigned to '$physical'" unless $zoneref->{type} == LOOPBACK;
	    fatal_error "Invalid definition of '$physical'"                   if $bridge ne $interface;
	    
	    for ( qw/arp_filter
		     arp_ignore
		     bridge
		     detectnets
		     dhcp
		     maclist
		     logmartians
		     norfc1918
		     nosmurts
		     proxyarp
		     routeback
		     routefilter
		     rpfilter
		     sfilter
		     sourceroute
		     upnp
		     upnpclient
		     mss
		    / ) {
		fatal_error "The '$config{LOOPBACK}' interface may not specify the '$_' option" if supplied $options{$_};
	    }
	} else {
	    fatal_error "A loopback zone may only be assigned to the loopback interface" if $zoneref->{type} == LOOPBACK;
	}

	$netsref ||= [ allip ];
	add_group_to_zone( $zone, $zoneref->{type}, $interface, $netsref, $hostoptionsref , 1);
	add_group_to_zone( $zone,
			   $zoneref->{type},
			   $interface,
			   $family == F_IPV4 ? [ IPv4_MULTICAST ] : [ IPv6_MULTICAST ] ,
			   { destonly => 1 },
			   0) if $hostoptionsref->{multicast} && $interfaces{$interface}{zone} ne $zone;
    }

    progress_message "  Interface \"$currentline\" Validated";

    return $interface;
}
```

## process_host (lines 2143–2281)

> hosts file row processor (full OPTIONS list)

```perl
sub process_host( ) {
    my $ipsec = 0;
    my ($zone, $hosts, $options ) = split_line1( 'hosts file',
						 { zone => 0, host => 1, hosts => 1, options => 2 },
						 {},
						 3 );

    fatal_error 'ZONE must be specified'  if $zone eq '-';
    fatal_error 'HOSTS must be specified' if $hosts eq '-';

    my $zoneref = $zones{$zone};
    my $type    = $zoneref->{type};

    fatal_error "Unknown ZONE ($zone)" unless $type;
    fatal_error 'Firewall zone not allowed in ZONE column of hosts record' if $type == FIREWALL;

    my ( $interface, $interfaceref );

    if ( $family == F_IPV4 ) {
	if ( $hosts =~ /^([\w.@%-]+\+?):(.*)$/ ) {
	    $interface = $1;
	    $hosts = $2;
	    fatal_error "Unknown interface ($interface)" unless ($interfaceref = $interfaces{$interface}) && $interfaceref->{root};
	    $interface = $interfaceref->{name};
	} else {
	    fatal_error "Invalid HOST(S) column contents: $hosts";
	}
    } elsif ( $hosts =~ /^([\w.@%-]+\+?):<(.*)>$/               ||
	      $hosts =~ /^([\w.@%-]+\+?)\[(.*)\]$/              ||
	      $hosts =~ /^([\w.@%-]+\+?):(!?\[.+\](?:\/\d+)?)$/ ||
	      $hosts =~ /^([\w.@%-]+\+?):(!?\+.*)$/             ||
	      $hosts =~ /^([\w.@%-]+\+?):(dynamic)$/ ) {
	$interface = $1;
	$hosts = $2;

	fatal_error "Unknown interface ($interface)" unless ($interfaceref = $interfaces{$interface}) && $interfaceref->{root};
	fatal_error "Unmanaged interfaces may not be associated with a zone" if $interfaceref->{unmanaged};
	$interface = $interfaceref->{name};
	if ( $interfaceref->{physical} eq $loopback_interface ) {
	    fatal_error "Only a loopback zone may be associated with the loopback interface ($loopback_interface)" if $type != LOOPBACK;
	} else {
	    fatal_error "Loopback zones may only be associated with the loopback interface ($loopback_interface)" if $type == LOOPBACK;
	}
    } else {
	fatal_error "Invalid HOST(S) column contents: $hosts"
    }

    if ( $hosts =~ /^!?\+/ ) {
       $zoneref->{complex} = 1;
       fatal_error "ipset name qualification is disallowed in this file" if $hosts =~ /[\[\]]/;
       fatal_error "Invalid ipset name ($hosts)" unless $hosts =~ /^!?\+[a-zA-Z][-\w]*$/;
    }

    if ( $type & BPORT ) {
	if ( $zoneref->{bridge} eq '' ) {
	    fatal_error 'Bridge Port Zones may only be associated with bridge ports' unless $interfaceref->{options}{port};
	    $zoneref->{bridge} = $interfaces{$interface}{bridge};
	} elsif ( $zoneref->{bridge} ne $interfaceref->{bridge} ) {
	    fatal_error "Interface $interface is not a port on bridge $zoneref->{bridge}";
	}
    }

    my $optionsref = { dynamic => 0 };

    if ( $options ne '-' ) {
	my @options = split_list $options, 'option';
	my %options = ( dynamic => 0 );

	for my $option ( @options ) {
	    if ( $option eq 'ipsec' ) {
		require_capability 'POLICY_MATCH' , q(The 'ipsec' option), 's';
		$type = IPSEC;
		$zoneref->{complex} = 1;
		$ipsec = $interfaceref->{ipsec} = 1;
	    } elsif ( $option eq 'norfc1918' ) {
		warning_message "The 'norfc1918' host option is no longer supported"
	    } elsif ( $option eq 'blacklist' ) {
		warning_message "The 'blacklist' option is no longer supported";
		$zoneref->{options}{in}{blacklist} = 1;
	    } elsif ( $option =~ /^mss=(\d+)$/ ) {
		fatal_error "Invalid mss ($1)" unless $1 >= 500;
		require_capability 'TCPMSS_TARGET', $option, 's';
		$options{mss} = $1;
		$zoneref->{options}{complex} = 1;
	    } elsif ( $validhostoptions{$option}) {
		fatal_error qq(The "$option" option is not allowed with Vserver zones) if $type & VSERVER && ! ( $validhostoptions{$option} & IF_OPTION_VSERVER );
		$options{$option} = 1;
	    } else {
		fatal_error "Invalid option ($option)";
	    }
	}

	fatal_error q(A host entry for a Vserver zone may not specify the 'ipsec' option) if $ipsec && $zoneref->{type} & VSERVER;

	$optionsref = \%options;
    }

    #
    # Looking for the '!' at the beginning of a list element is more straight-foward than looking for it in the middle.
    #
    # Be sure we don't have a ',!' in the original
    #
    fatal_error "Invalid hosts list" if $hosts =~ /,!/;
    #
    # Now add a comma before '!'. Do it globally - add_group_to_zone() correctly checks for multiple exclusions
    #
    $hosts =~ s/!/,!/g;
    #
    # Take care of case where the hosts list begins with '!'
    #
    $hosts = join( '', ALLIP , $hosts ) if substr($hosts, 0, 2 ) eq ',!';

    if ( $hosts eq 'dynamic' ) {
	fatal_error "Vserver zones may not be dynamic" if $type & VSERVER;
	require_capability( 'IPSET_MATCH', 'Dynamic nets', '');

	my $set = $family == F_IPV4 ? "${zone}" : "6_${zone}";
	
	unless ( $zoneref->{options}{in_out}{dynamic_shared} ) {
	    my $physical = var_base1( physical_name $interface );
	    $set = join( '_', $set, $physical );
	}

	$hosts = "+$set";
	$optionsref->{dynamic} = 1;
	add_ipset($set);
    }

    #
    # We ignore the user's notion of what interface vserver addresses are on and simply invent one for all of the vservers.
    #
    $interface = '%vserver%' if $type & VSERVER;

    add_group_to_zone( $zone, $type , $interface, [ split_list( $hosts, 'host' ) ] , $optionsref, 0 );

    progress_message "   Host \"$currentline\" validated";

    return $ipsec;
}
```
