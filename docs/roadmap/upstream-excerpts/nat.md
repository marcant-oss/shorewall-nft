# Nat.pm — extracted functions

**Source**: `Shorewall/Perl/Shorewall/Nat.pm`
**Git tag**: 5.2.6.1
**Purpose**: Reference for shorewall-nft Phase 6 work-package agents.

## Index

- `process_one_masq1` (lines 63–403): worker for one masq file row
- `process_one_masq` (lines 506–542): dispatcher (convert or process)
- `do_one_nat` (lines 677–736): classic 1:1 NAT row processor
- `setup_nat` (lines 741–768): NAT file orchestrator
- `add_addresses` (lines 1109–1128): emits shell commands to add IP aliases

## process_one_masq1 (lines 63–403)

> worker for one masq file row

```perl
sub process_one_masq1( $$$$$$$$$$$ )
{
    my ( $interfacelist, $networks, $addresses, $proto, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability ) = @_;

    my $pre_nat;
    my $add_snat_aliases = $family == F_IPV4 && $config{ADD_SNAT_ALIASES};
    my $destnets = '';
    my $baserule = '';
    my $inlinematches = '';
    my $prerule       = '';
    my $savelist;
    #
    # Leading '+'
    #
    $pre_nat = 1 if $interfacelist =~ s/^\+//;

    #
    # Check for INLINE
    #
    if ( $interfacelist =~ /^INLINE\((.+)\)$/ ) {
	$interfacelist = $1;
	$inlinematches = get_inline_matches(0);
    } else {
	$inlinematches = get_inline_matches(0);
    }

    $savelist = $interfacelist;
    #
    # Handle early matches
    #
    if ( $inlinematches =~ s/^s*\+// ) {
	$prerule = $inlinematches;
	$inlinematches = '';
    }
    #
    # Parse the remaining part of the INTERFACE column
    #
    if ( $family == F_IPV4 ) {
	if ( $interfacelist =~ /^([^:]+)::([^:]*)$/ ) {
	    $add_snat_aliases = 0;
	    $destnets = $2;
	    $interfacelist = $1;
	} elsif ( $interfacelist =~ /^([^:]+:[^:]+):([^:]+)$/ ) {
	    $destnets = $2;
	    $interfacelist = $1;
	} elsif ( $interfacelist =~ /^([^:]+):$/ ) {
	    $add_snat_aliases = 0;
	    $interfacelist = $1;
	} elsif ( $interfacelist =~ /^([^:]+):([^:]*)$/ ) {
	    my ( $one, $two ) = ( $1, $2 );
	    if ( $2 =~ /\./ || $2 =~ /^%/ ) {
		$interfacelist = $one;
		$destnets = $two;
	    }
	}
    } elsif ( $interfacelist =~ /^(.+?):(.+)$/ ) {
	$interfacelist = $1;
	$destnets      = $2;
    }
    #
    # If there is no source or destination then allow all addresses
    #
    $networks = ALLIP if $networks eq '-';
    $destnets = ALLIP if $destnets eq '-';

    #
    # Handle IPSEC options, if any
    #
    if ( $ipsec ne '-' ) {
	fatal_error "Non-empty IPSEC column requires policy match support in your kernel and iptables"  unless have_capability( 'POLICY_MATCH' );

	if ( $ipsec =~ /^yes$/i ) {
	    $baserule .= do_ipsec_options 'out', 'ipsec', '';
	} elsif ( $ipsec =~ /^no$/i ) {
	    $baserule .= do_ipsec_options 'out', 'none', '';
	} else {
	    $baserule .= do_ipsec_options 'out', 'ipsec', $ipsec;
	}
    } elsif ( have_ipsec ) {
	$baserule .= '-m policy --pol none --dir out ';
    }

    #
    # Handle Protocol, Ports and Condition
    #
    $baserule .= do_proto( $proto, $ports, '' );
    #
    # Handle Mark
    #
    $baserule .= do_test( $mark, $globals{TC_MASK} ) if $mark ne '-';
    $baserule .= do_user( $user )                    if $user ne '-';
    $baserule .= do_probability( $probability )      if $probability ne '-';

    my $target;

    for my $fullinterface (split_list $interfacelist, 'interface' ) {
	my $rule = '';

	$target = 'MASQUERADE ';
	#
	# Isolate and verify the interface part
	#
	( my $interface = $fullinterface ) =~ s/:.*//;

	if ( $interface =~ /(.*)[(](\w*)[)]$/ ) {
	    $interface = $1;
	    my $provider  = $2;

	    fatal_error "Missing Provider ($fullinterface)" unless supplied $provider;

	    $fullinterface =~ s/[(]\w*[)]//;
	    my $realm = provider_realm( $provider );

	    fatal_error "$provider is not a shared-interface provider" unless $realm;

	    $rule .= "-m realm --realm $realm ";
	}

	fatal_error "Unknown interface ($interface)" unless my $interfaceref = known_interface( $interface );

	if ( $interfaceref->{root} ) {
	    $interface = $interfaceref->{name} if $interface eq $interfaceref->{physical};
	} else {
	    $rule .= match_dest_dev( $interface );
	    $interface = $interfaceref->{name};
	}

	my $chainref = ensure_chain('nat', $pre_nat ? snat_chain $interface : masq_chain $interface);

	$baserule .= do_condition( $condition , $chainref->{name} );

	my $detectaddress = 0;
	my $exceptionrule = '';
	my $randomize     = '';
	my $persistent    = '';
	my $conditional   = 0;
	#
	# Parse the ADDRESSES column
	#
	if ( $addresses ne '-' ) {
	    my $saveaddresses = $addresses;
	    if ( $addresses eq 'random' ) {
		require_capability( 'MASQUERADE_TGT', 'Masquerade rules', '') if $family == F_IPV6;
		$randomize = '--random ';
	    } else {
		$addresses =~ s/:persistent$// and $persistent = ' --persistent ';
		$addresses =~ s/:random$//     and $randomize  = ' --random ';

		require_capability 'PERSISTENT_SNAT', ':persistent', 's' if $persistent;

		if ( $addresses =~ /^SAME/ ) {
		    fatal_error "The SAME target is no longer supported";
		} elsif ( $addresses eq 'detect' ) {
		    my $variable = get_interface_address $interface;
		    $target = "SNAT --to-source $variable";

		    if ( interface_is_optional $interface ) {
			add_commands( $chainref,
				      '',
				      "if [ \"$variable\" != 0.0.0.0 ]; then" );
			incr_cmd_level( $chainref );
			$detectaddress = 1;
		    }
		} elsif ( $addresses eq 'NONAT' ) {
		    fatal_error "'persistent' may not be specified with 'NONAT'" if $persistent;
		    fatal_error "'random' may not be specified with 'NONAT'"     if $randomize;
		    $target = 'RETURN';
		    $add_snat_aliases = 0;
		} elsif ( $addresses ) {
		    my $addrlist = '';
		    my @addrs = split_list $addresses, 'address';

		    fatal_error "Only one ADDRESS may be specified" if @addrs > 1;

		    for my $addr ( @addrs ) {
			if ( $addr =~ /^([&%])(.+)$/ ) {
			    my ( $type, $interface ) = ( $1, $2 );

			    my $ports = '';

			    if ( $interface =~ s/:(.+)$// ) {
				validate_portpair1( $proto, $1 );
				$ports = ":$1";
			    }
			    #
			    # Address Variable
			    #
			    $target = 'SNAT ';

			    if ( $interface =~ /^{([a-zA-Z_]\w*)}$/ ) {
				#
				# User-defined address variable
				#
				$conditional = conditional_rule( $chainref, $addr );
				$addrlist .= '--to-source ' . "\$${1}${ports} ";
			    } else {
				if ( $conditional = conditional_rule( $chainref, $addr ) ) {
				    #
				    # Optional Interface -- rule is conditional
				    #
				    $addr = get_interface_address $interface;
				} else {
				    #
				    # Interface is not optional
				    #
				    $addr = record_runtime_address( $type, $interface );
				}

				if ( $ports ) {
				    $addr =~ s/ $//;
				    $addr = $family == F_IPV4 ? "${addr}${ports} " : "[$addr]$ports ";
				}

				$addrlist .= '--to-source ' . $addr;
			    }
			} elsif ( $family == F_IPV4 ) {
			    if ( $addr =~ /^.*\..*\..*\./ ) {
				$target = 'SNAT ';
				my ($ipaddr, $rest) = split ':', $addr, 2;
				if ( $ipaddr =~ /^(.+)-(.+)$/ ) {
				    validate_range( $1, $2 );
				} else {
				    validate_address $ipaddr, 0;
				}

				if ( supplied $rest ) {
				    validate_portpair1( $proto, $rest );
				    $addrlist .= "--to-source $addr ";
				} else {
				    $addrlist .= "--to-source $ipaddr";
				}

				$exceptionrule = do_proto( $proto, '', '' ) if $addr =~ /:/;
			    } else {
				my $ports = $addr;
				$ports =~ s/^://;
				validate_portpair1( $proto, $ports );
				$addrlist .= "--to-ports $ports ";
				$exceptionrule = do_proto( $proto, '', '' );
			    }
			} else {
			    $target = 'SNAT ';

			    if ( $addr =~ /^\[/ ) {
				#
				# Can have ports specified
				#
				my $ports;

				if ( $addr =~ s/:([^]:]+)$// ) {
				    $ports = $1;
				}

				fatal_error "Invalid IPv6 Address ($addr)" unless $addr =~ /^\[(.+)\]$/;

				$addr = $1;
				$addr =~ s/\]-\[/-/;

				if ( $addr =~ /^(.+)-(.+)$/ ) {
				    validate_range( $1, $2 );
				} else {
				    validate_address $addr, 0;
				}

				if ( supplied $ports ) {
				    validate_portpair1( $proto, $ports );
				    $exceptionrule = do_proto( $proto, '', '' );
				    $addr = "[$addr]:$ports";
				}

				$addrlist .= "--to-source $addr ";
			    } else {
				if ( $addr =~ /^(.+)-(.+)$/ ) {
				    validate_range( $1, $2 );
				} else {
				    validate_address $addr, 0;
				}

				$addrlist .= "--to-source $addr ";
			    }
			}
		    }

		    $target .= $addrlist;
		} else {
		    fatal_error( "':persistent' is not allowed in a MASQUERADE rule" ) if $persistent;
		    require_capability( 'MASQUERADE_TGT', 'Masquerade rules', '' )     if $family == F_IPV6;
		}
	    }

	    $target .= $randomize;
	    $target .= $persistent;
	    $addresses = $saveaddresses;
	} else {
	    require_capability( 'MASQUERADE_TGT', 'Masquerade rules', '' )  if $family == F_IPV6;
	    $add_snat_aliases = 0;
	}
	#
	# And Generate the Rule(s)
	#
	expand_rule( $chainref ,
		     POSTROUTE_RESTRICT ,
		     $prerule ,
		     $baserule . $inlinematches . $rule ,
		     $networks ,
		     $destnets ,
		     $origdest ,
		     $target ,
		     '' ,
		     '' ,
		     $exceptionrule ,
		     '' )
	    unless unreachable_warning( 0, $chainref );

	conditional_rule_end( $chainref ) if $detectaddress || $conditional;

	if ( $add_snat_aliases ) {
	    my ( $interface, $alias , $remainder ) = split( /:/, $fullinterface, 3 );
	    fatal_error "Invalid alias ($alias:$remainder)" if defined $remainder;
	    for my $address ( split_list $addresses, 'address' ) {
		my ( $addrs, $port ) = split /:/, $address;
		next unless $addrs;
		next if $addrs eq 'detect';
		for my $addr ( ip_range_explicit $addrs ) {
		    unless ( $addresses_to_add{$addr} ) {
			$addresses_to_add{$addr} = 1;
			if ( defined $alias ) {
			    push @addresses_to_add, $addr, "$interface:$alias";
			    $alias++;
			} else {
			    push @addresses_to_add, $addr, $interface;
			}
		    }
		}
	    }
	}
    }

    progress_message "   Masq record \"$currentline\" $done";

}
```

## process_one_masq (lines 506–542)

> dispatcher (convert or process)

```perl
sub process_one_masq( $ )
{
    my ( $snat ) = @_;

    if ( $snat ) {
	unless ( $rawcurrentline =~ /^\s*(?:#.*)?$/ ) {
	    #
	    # Line was not blank or all comment
	    #
	    my ($interfacelist, $networks, $addresses, $protos, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability ) =
		split_rawline2( 'masq file',
				{ interface => 0, source => 1, address => 2, proto => 3, port => 4, ipsec => 5, mark => 6, user => 7, switch => 8, origdest => 9, probability => 10 },
				{},    #Nopad
				undef, #Columns
				1 );   #Allow inline matches

	    if ( $interfacelist ne '-' ) { 
		for my $proto ( split_list $protos, 'Protocol' ) {
		    convert_one_masq1( $snat, $interfacelist, $networks, $addresses, $proto, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability );
		}
	    }
	}
    } else {
	my ($interfacelist, $networks, $addresses, $protos, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability ) =
	    split_line2( 'masq file',
			 { interface => 0, source => 1, address => 2, proto => 3, port => 4, ipsec => 5, mark => 6, user => 7, switch => 8, origdest => 9, probability => 10 },
			 {},    #Nopad
			 undef, #Columns
			 1 );   #Allow inline matches

	fatal_error 'INTERFACE must be specified' if $interfacelist eq '-';

	for my $proto ( split_list $protos, 'Protocol' ) {
	    process_one_masq1( $interfacelist, $networks, $addresses, $proto, $ports, $ipsec, $mark, $user, $condition, $origdest, $probability );
	}
    }
}
```

## do_one_nat (lines 677–736)

> classic 1:1 NAT row processor

```perl
sub do_one_nat( $$$$$ )
{
    my ( $external, $fullinterface, $internal, $allints, $localnat ) = @_;

    my ( $interface, $alias, $remainder ) = split( /:/, $fullinterface, 3 );

    fatal_error "Invalid alias ($alias:$remainder)" if defined $remainder;

    sub add_nat_rule( $$ ) {
	add_rule ensure_chain( 'nat', $_[0] ) , $_[1];
    }

    my $add_ip_aliases = $config{ADD_IP_ALIASES};

    my $policyin = '';
    my $policyout = '';
    my $rulein = '';
    my $ruleout = '';

    fatal_error "Unknown interface ($interface)" unless my $interfaceref = known_interface( $interface );

    if ( $interfaceref->{root} ) {
	$interface = $interfaceref->{name} if $interface eq $interfaceref->{physical};
    } else {
	$rulein  = match_source_dev $interface;
	$ruleout = match_dest_dev $interface;
	$interface = $interfaceref->{name};
    }

    if ( have_ipsec ) {
	$policyin = ' -m policy --pol none --dir in';
	$policyout =  '-m policy --pol none --dir out';
    }

    fatal_error "Invalid nat file entry" unless defined $interface && defined $internal;

    if ( $add_ip_aliases ) {
	$add_ip_aliases = '' if defined( $alias ) && $alias eq '';
    }

    validate_nat_column 'ALL INTERFACES', \$allints;
    validate_nat_column 'LOCAL'         , \$localnat;

    if ( $allints ) {
	add_nat_rule 'nat_in' ,  "-d $external $policyin  -j DNAT --to-destination $internal";
	add_nat_rule 'nat_out' , "-s $internal $policyout -j SNAT --to-source $external";
    } else {
	add_nat_rule input_chain( $interface ) ,  $rulein  . "-d $external $policyin -j DNAT --to-destination $internal";
	add_nat_rule output_chain( $interface ) , $ruleout . "-s $internal $policyout -j SNAT --to-source $external";
    }

    add_nat_rule 'OUTPUT' , "-d $external $policyout -j DNAT --to-destination $internal " if $localnat;

    if ( $add_ip_aliases ) {
	unless ( $addresses_to_add{$external} ) {
	    $addresses_to_add{$external} = 1;
	    push @addresses_to_add, ( $external , $fullinterface );
	}
    }
}
```

## setup_nat (lines 741–768)

> NAT file orchestrator

```perl
sub setup_nat() {

    if ( my $fn = open_file( 'nat', 1, 1 ) ) {

	first_entry( sub { progress_message2 "$doing $fn..."; require_capability 'NAT_ENABLED' , 'a non-empty nat file' , 's'; } );

	while ( read_a_line( NORMAL_READ ) ) {

	    my ( $external, $interfacelist, $internal, $allints, $localnat ) =
		split_line1( 'nat file',
			     { external => 0, interface => 1, internal => 2, allints => 3, local => 4 } );

	    ( $interfacelist, my $digit ) = split /:/, $interfacelist;

	    $digit = defined $digit ? ":$digit" : '';

	    fatal_error 'EXTERNAL must be specified' if $external eq '-';
	    fatal_error 'INTERNAL must be specified' if $interfacelist eq '-';

	    for my $interface ( split_list $interfacelist , 'interface' ) {
		fatal_error "Invalid Interface List ($interfacelist)" unless supplied $interface;
		do_one_nat $external, "${interface}${digit}", $internal, $allints, $localnat;
	    }

	    progress_message "   NAT entry \"$currentline\" $done";
	}
    }
}
```

## add_addresses (lines 1109–1128)

> emits shell commands to add IP aliases

```perl
sub add_addresses () {
    if ( @addresses_to_add ) {
	my @addrs = @addresses_to_add;
	my $arg = '';
	my $addresses = 0;

	while ( @addrs ) {
	    my $addr      = shift @addrs;
	    my $interface = shift @addrs;
	    $arg = "$arg $addr $interface";
	    unless ( $config{RETAIN_ALIASES} ) {
		emit '' unless $addresses++;
		$interface =~ s/:.*//;
		emit "del_ip_addr $addr $interface";
	    }
	}

	emit "\nadd_ip_aliases $arg";
    }
}
```

## Functions referenced elsewhere

- `process_snat1` / `process_snat` — modern SNAT file processor in **Rules.pm** (lines 5552, 6030). See `rules.md`.
