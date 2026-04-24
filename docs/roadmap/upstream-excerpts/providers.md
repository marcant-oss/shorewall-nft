# Providers.pm — extracted functions

**Source**: `Shorewall/Perl/Shorewall/Providers.pm`
**Git tag**: 5.2.6.1
**Purpose**: Reference for shorewall-nft Phase 6 work-package agents.

## Index

- `process_a_provider` (lines 474–826): main provider row processor
- `add_a_provider` (lines 844–1324): generates start_provider_X / stop_provider_X shell functions
- `add_an_rtrule1` (lines 1326–1422): adds a single routing rule to a provider
- `add_an_rtrule` (lines 1424–1433): rtrules file row dispatcher
- `add_a_route` (lines 1435–1529): routes file row dispatcher
- `process_providers` (lines 1712–1885): reads providers/rtrules/routes files; calls add_a_provider for each
- `setup_providers` (lines 1920–1989): orchestrator

## process_a_provider (lines 474–826)

> main provider row processor

```perl
sub process_a_provider( $ ) {
    my $pseudo = $_[0]; # When true, this is an optional interface that we are treating somewhat like a provider.

    my ($table, $number, $mark, $duplicate, $interface, $gateway,  $options, $copy ) =
	split_line('providers file',
		   { table => 0, number => 1, mark => 2, duplicate => 3, interface => 4, gateway => 5, options => 6, copy => 7 } );

    fatal_error "Duplicate provider ($table)" if $providers{$table};

    fatal_error 'NAME must be specified' if $table eq '-';

    unless ( $pseudo ) {
	fatal_error "Invalid Provider Name ($table)" unless $table =~ /^[A-Za-z][\w]*$/;

	my $num = numeric_value $number;

	fatal_error 'NUMBER must be specified' if $number eq '-';
	fatal_error "Invalid Provider number ($number)" unless defined $num;

	$number = $num;

	for my $providerref ( values %providers  ) {
	    fatal_error "Duplicate provider number ($number)" if $providerref->{number} == $number;
	}
    }

    fatal_error 'INTERFACE must be specified' if $interface eq '-';

    ( $interface, my $address ) = split /:/, $interface, 2;

    my $shared = 0;
    my $noautosrc = 0;
    my $mac = '';

    if ( defined $address ) {
	validate_address $address, 0;
	$shared = 1;
	require_capability 'REALM_MATCH', "Configuring multiple providers through one interface", "s";
    }

    my $interfaceref = known_interface( $interface );

    fatal_error "Unknown Interface ($interface)" unless $interfaceref;

    fatal_error "A bridge port ($interface) may not be configured as a provider interface" if port_to_bridge $interface;

    #
    # Switch to the logical name if a physical name was passed
    #
    my $physical;

    if ( $interface eq $interfaceref->{name} ) {
	#
	# The logical interface name was specified
	#
	$physical = $interfaceref->{physical};
    } else {
	#
	# A Physical name was specified
	#
	$physical = $interface;
	#
	# Switch to the logical name unless it is a wildcard
	#
	$interface = $interfaceref->{name} unless $interfaceref->{wildcard};
    } 

    if ( $physical =~ /\+$/ ) {
	return 0 if $pseudo;
	fatal_error "Wildcard interfaces ($physical) may not be used as provider interfaces";
    }

    my $gatewaycase = '';
    my $gw;

    if ( ( $gw = lc $gateway ) eq 'detect' ) {
	fatal_error "Configuring multiple providers through one interface requires an explicit gateway" if $shared;
	$gateway = get_interface_gateway( $interface, undef, $number );
	$gatewaycase = 'detect';
	set_interface_option( $interface, 'gateway', 'detect' );
    } elsif ( $gw eq 'none' ) {
	fatal_error "Configuring multiple providers through one interface requires a gateway" if $shared;
	$gatewaycase = 'none';
	$gateway = '';
	set_interface_option( $interface, 'gateway', 'none' );
    } elsif ( $gateway && $gateway ne '-' ) {
	( $gateway, $mac ) = split_host_list( $gateway, 0 );

	$gateway = $1 if $family == F_IPV6 && $gateway =~ /^\[(.+)\]$/;

	validate_address $gateway, 0;

	if ( defined $mac ) {
	    $mac =~ tr/-/:/;
	    $mac =~ s/^~//;
	    fatal_error "Invalid MAC address ($mac)" unless $mac =~ /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
	} else {
	    $mac = '';
	}

	$gatewaycase = 'specified';
	set_interface_option( $interface, 'gateway', $gateway );
    } else {
	$gatewaycase = 'omitted';
	fatal_error "Configuring multiple providers through one interface requires a gateway" if $shared;
	$gateway = '';
	set_interface_option( $interface, 'gateway', $pseudo ? 'detect' : 'omitted' );
    }


    my ( $loose, $track, $balance, $default, $default_balance, $optional, $mtu, $tproxy, $local, $load, $what, $hostroute, $persistent );

    if ( $pseudo ) {	
	( $loose, $track,                   $balance , $default, $default_balance,                   $optional,                           $mtu, $tproxy , $local, $load, $what ,      $hostroute,        $persistent ) =
	( 0,      0                       , 0 ,        0,        0,                                  1                                  , ''  , 0       , 0,      0,     'interface', 0,                 0);
    } else {
	( $loose, $track,                   $balance , $default, $default_balance,                   $optional,                           $mtu, $tproxy , $local, $load, $what      , $hostroute,        $persistent  )=
	( 0,      $config{TRACK_PROVIDERS}, 0 ,        0,        $config{BALANCE_PROVIDERS} ? 1 : 0, interface_is_optional( $interface ), ''  , 0       , 0,      0,     'provider',  1,                 0);
    }

    unless ( $options eq '-' ) {
	for my $option ( split_list $options, 'option' ) {
	    if ( $option eq 'track' ) {
		require_mangle_capability( 'MANGLE_ENABLED' , q(The 'track' option) , 's' );
		$track = 1;
	    } elsif ( $option eq 'notrack' ) {
		$track = 0;
	    } elsif ( $option =~ /^balance=(\d+)$/ ) {
		fatal_error q('balance' may not be spacified when GATEWAY is 'none') if $gatewaycase eq 'none';
		fatal_error 'The balance setting must be non-zero' unless $1;
		$balance = $1;
	    } elsif ( $option eq 'balance' || $option eq 'primary') {
		fatal_error qq('$option' may not be spacified when GATEWAY is 'none') if $gatewaycase eq 'none';
		$balance = 1;
	    } elsif ( $option eq 'loose' ) {
		$loose   = 1;
		$default_balance = 0;
	    } elsif ( $option eq 'optional' ) {
		unless ( $shared ) {
		    warning_message q(The 'optional' provider option is deprecated - use the 'optional' interface option instead);
		    set_interface_option $interface, 'optional', 1;
		}

		$optional = 1;
	    } elsif ( $option =~ /^src=(.*)$/ ) {
		fatal_error "OPTION 'src' not allowed on shared interface" if $shared;
		$address = validate_address( $1 , 1 );
	    } elsif ( $option =~ /^mtu=(\d+)$/ ) {
		$mtu = "mtu $1 ";
	    } elsif ( $option =~ /^fallback=(\d+)$/ ) {
		fatal_error q('fallback' may not be spacified when GATEWAY is 'none') if $gatewaycase eq 'none';
		$default = $1;
		$default_balance = 0;
		fatal_error 'fallback must be non-zero' unless $default;
	    } elsif ( $option eq 'fallback' ) {
		fatal_error q('fallback' may not be spacified when GATEWAY is 'none') if $gatewaycase eq 'none';
		$default = -1;
		$default_balance = 0;
	    } elsif ( $option eq 'local' ) {
		warning_message q(The 'local' provider option is deprecated in favor of 'tproxy');
		$local = $tproxy = 1;
		$track  = 0           if $config{TRACK_PROVIDERS};
		$default_balance = 0  if $config{USE_DEFAULT_RT};
	    } elsif ( $option eq 'tproxy' ) {
		$tproxy = 1;
		$track  = 0           if $config{TRACK_PROVIDERS};
		$default_balance = 0  if $config{USE_DEFAULT_RT};
	    } elsif ( $option =~ /^load=(0?\.\d{1,8})/ ) {
		fatal_error q('fallback' may not be spacified when GATEWAY is 'none') if $gatewaycase eq 'none';
		$load = sprintf "%1.8f", $1;
		require_capability 'STATISTIC_MATCH', "load=$1", 's';
	    } elsif ( $option eq 'autosrc' ) {
		$noautosrc = 0;
	    } elsif ( $option eq 'noautosrc' ) {
		$noautosrc = 1;
	    } elsif ( $option eq 'hostroute' ) {
		$hostroute = 1;
	    } elsif ( $option eq 'nohostroute' ) {
		$hostroute = 0;
	    } elsif ( $option eq 'persistent' ) {
		warning_message "When RESTORE_DEFAULT_ROUTE=Yes, the 'persistent' option may not work as expected" if $config{RESTORE_DEFAULT_ROUTE};
		$persistent = 1;
	    } else {
		fatal_error "Invalid option ($option)";
	    }
	}
    }

    if ( $balance ) {
	fatal_error q(The 'balance' and 'fallback' options are mutually exclusive) if $default;
	$balanced_providers++;
    } elsif ( $default ) {
	$fallback_providers++;
    }

    if ( $load ) {
	fatal_error q(The 'balance=<weight>' and 'load=<load-factor>' options are mutually exclusive) if $balance > 1;
	fatal_error q(The 'fallback=<weight>' and 'load=<load-factor>' options are mutually exclusive) if $default > 1;
	$maxload += $load;
    }

    fatal_error "A provider interface must have at least one associated zone" unless $tproxy || %{interface_zones($interface)};
    fatal_error "An interface supporting multiple providers may not be optional" if $shared && $optional;

    unless ( $pseudo ) {
	if ( $local ) {
	    fatal_error "GATEWAY not valid with 'local' provider"  unless $gatewaycase eq 'omitted';
	    fatal_error "'track' not valid with 'local'"           if $track;
	    fatal_error "DUPLICATE not valid with 'local'"         if $duplicate ne '-';
	    fatal_error "'persistent' is not valid with 'local"    if $persistent;
	} elsif ( $tproxy ) {
	    fatal_error "Only one 'tproxy' provider is allowed"    if $tproxies++;
	    fatal_error "GATEWAY not valid with 'tproxy' provider" unless $gatewaycase eq 'omitted';
	    fatal_error "'track' not valid with 'tproxy'"          if $track;
	    fatal_error "DUPLICATE not valid with 'tproxy'"        if $duplicate ne '-';
	    fatal_error "MARK not allowed with 'tproxy'"           if $mark ne '-';
	    fatal_error "'persistent' is not valid with 'tproxy"   if $persistent;
	    $mark = $globals{TPROXY_MARK};
	} elsif ( ( my $rf = ( $config{ROUTE_FILTER} eq 'on' ) ) || $interfaceref->{options}{routefilter} ) {
	    if ( $config{USE_DEFAULT_RT} ) {
		if ( $rf ) {
		    fatal_error "There may be no providers when ROUTE_FILTER=Yes and USE_DEFAULT_RT=Yes";
		} else {
		    fatal_error "Providers interfaces may not specify 'routefilter' when USE_DEFAULT_RT=Yes";
		}
	    } else {
		unless ( $balance ) {
		    if ( $rf ) {
			fatal_error "The 'balance' option is required when ROUTE_FILTER=Yes";
		    } else {
			fatal_error "Provider interfaces may not specify 'routefilter' without 'balance' or 'primary'";
		    }
		}
	    }
	}
    }

    my $val = 0;
    my $pref;

    $mark = ( $lastmark += ( 1 << $config{PROVIDER_OFFSET} ) ) if $mark eq '-' && $track;

    if ( $mark ne '-' ) {
	require_mangle_capability( 'MANGLE_ENABLED' , 'Provider marks' , '' );

	if ( $tproxy && ! $local ) {
	    $val = $globals{TPROXY_MARK};
	    $pref = 1;
	} else {
	    $val = numeric_value $mark;

	    fatal_error "Invalid Mark Value ($mark)" unless defined $val && $val;

	    verify_mark $mark;

	    fatal_error "Invalid Mark Value ($mark)" unless ( $val & $globals{PROVIDER_MASK} ) == $val;

	    fatal_error "Provider MARK may not be specified when PROVIDER_BITS=0" unless $config{PROVIDER_BITS};

	    for my $providerref ( values %providers  ) {
		fatal_error "Duplicate mark value ($mark)" if numeric_value( $providerref->{mark} ) == $val;
	    }

	    $lastmark = $val;
	    
	    $pref = 10000 + $number - 1;
	}
    }

    unless ( $loose || $pseudo ) {
	warning_message q(The 'proxyarp' option is dangerous when specified on a Provider interface) if get_interface_option( $interface, 'proxyarp' );
	warning_message q(The 'proxyndp' option is dangerous when specified on a Provider interface) if get_interface_option( $interface, 'proxyndp' );
    }

    $balance = $default_balance unless $balance || $gatewaycase eq 'none';

    fatal_error "Interface $interface is already associated with non-shared provider $provider_interfaces{$interface}" if $provider_interfaces{$interface};

    if ( $duplicate ne '-' ) {
	fatal_error "The DUPLICATE column must be empty when USE_DEFAULT_RT=Yes" if $config{USE_DEFAULT_RT};
	my $p = lookup_provider( $duplicate );
	my $n = $p ? $p->{number} : 0;
	warning_message "Unknown routing table ($duplicate)" unless $n && ( $n == MAIN_TABLE || $n < BALANCE_TABLE );
	warning_message "An optional provider ($duplicate) is listed in the DUPLICATE column - enable and disable will not work correctly on that provider" if $p && $p->{optional};
    } elsif ( $copy ne '-' ) {
	fatal_error "The COPY column must be empty when USE_DEFAULT_RT=Yes" if $config{USE_DEFAULT_RT};
	fatal_error 'A non-empty COPY column requires that a routing table be specified in the DUPLICATE column' unless $copy eq 'none';
    }

    if ( $persistent ) {
	warning_message( "Provider $table is not optional -- the 'persistent' option is ignored" ), $persistent = 0 unless $optional;
    }

    $providers{$table} = { provider          => $table,
			   number            => $number ,
			   id                => $config{USE_RT_NAMES} ? $table : $number,
			   rawmark           => $mark ,
			   mark              => $val ? in_hex($val) : $val ,
			   interface         => $interface ,
			   physical          => $physical ,
			   optional          => $optional ,
			   wildcard          => $interfaceref->{wildcard} || 0,
			   gateway           => $gateway ,
			   gatewaycase       => $gatewaycase ,
			   shared            => $shared ,
			   default           => $default ,
			   copy              => $copy ,
			   balance           => $balance ,
			   pref              => $pref ,
			   mtu               => $mtu ,
			   noautosrc         => $noautosrc ,
			   track             => $track ,
			   loose             => $loose ,
			   duplicate         => $duplicate ,
			   address           => $address ,
			   mac               => $mac ,
			   local             => $local ,
			   tproxy            => $tproxy ,
			   load              => $load ,
			   pseudo            => $pseudo ,
			   what              => $what ,
			   hostroute         => $hostroute ,
			   rules             => [] ,
			   persistent_rules  => [] ,
			   routes            => [] ,
			   persistent_routes => [],
			   routedests        => {} ,
			   persistent        => $persistent,
			   origin            => shortlineinfo( '' ),
			 };

    $provider_interfaces{$interface} = $table unless $shared;

    if ( $track ) {
	if ( $routemarked_interfaces{$interface} ) {
	    fatal_error "Interface $interface is tracked through an earlier provider" if $routemarked_interfaces{$interface} == ROUTEMARKED_UNSHARED;
	    fatal_error "Multiple providers through the same interface must have their IP address specified in the INTERFACES column" unless $shared;
	} else {
	    $routemarked_interfaces{$interface} = $shared ? ROUTEMARKED_SHARED : ROUTEMARKED_UNSHARED;
	    push @routemarked_interfaces, $interface;
	}

	push @routemarked_providers, $providers{$table};
    }

    push @load_providers, $table if $load;

    push @providers, $table;

    progress_message "   Provider \"$currentline\" $done" unless $pseudo;

    return 1;
}
```

## add_a_provider (lines 844–1324)

> generates start_provider_X / stop_provider_X shell functions

```perl
sub add_a_provider( $$ ) {

    my ( $providerref, $tcdevices ) = @_;

    my $table       = $providerref->{provider};
    my $number      = $providerref->{number};
    my $id          = $providerref->{id};
    my $mark        = $providerref->{rawmark};
    my $interface   = $providerref->{interface};
    my $physical    = $providerref->{physical};
    my $optional    = $providerref->{optional};
    my $gateway     = $providerref->{gateway};
    my $gatewaycase = $providerref->{gatewaycase};
    my $shared      = $providerref->{shared};
    my $default     = $providerref->{default};
    my $copy        = $providerref->{copy};
    my $balance     = $providerref->{balance};
    my $pref        = $providerref->{pref};
    my $mtu         = $providerref->{mtu};
    my $noautosrc   = $providerref->{noautosrc};
    my $track       = $providerref->{track};
    my $loose       = $providerref->{loose};
    my $duplicate   = $providerref->{duplicate};
    my $address     = $providerref->{address};
    my $mac         = $providerref->{mac};
    my $local       = $providerref->{local};
    my $tproxy      = $providerref->{tproxy};
    my $load        = $providerref->{load};
    my $pseudo      = $providerref->{pseudo};
    my $what        = $providerref->{what};
    my $label       = $pseudo ? 'Optional Interface' : 'Provider';
    my $hostroute   = $providerref->{hostroute};
    my $persistent  = $providerref->{persistent};

    my $dev         = var_base $physical;
    my $base        = uc $dev;
    my $realm = '';

    if ( $persistent ) {
	emit( '',
	      '#',
	      "# Persistent $what $table is currently disabled",
	      '#',
	      "do_persistent_${what}_${table}() {" );

	push_indent;

	emit( "if interface_is_up $physical; then" );

	push_indent;

	if ( $gatewaycase eq 'omitted' ) {
	    if ( $tproxy ) {
		emit 'run_ip route add local ' . ALLIP . " dev $physical table $id";
	    } else {
		emit "run_ip route replace default dev $physical table $id";
	    }
	}

	if ( $gateway ) {
	    $address = get_interface_address( $interface, 1 ) unless $address;

	    emit( qq([ -z "$address" ] && return\n) );

	    if ( $hostroute ) {
		emit qq(run_ip route replace $gateway src $address dev $physical ${mtu});
		emit qq(run_ip route replace $gateway src $address dev $physical ${mtu}table $id $realm);
		emit qq(echo "\$IP route del $gateway src $address dev $physical ${mtu} > /dev/null 2>&1" >> \${VARDIR}/undo_${table}_routing);
		emit qq(echo "\$IP route del $gateway src $address dev $physical ${mtu}table $id $realm > /dev/null 2>&1" >> \${VARDIR}/undo_${table}_routing);
	    }

	    emit( "run_ip route replace default via $gateway src $address dev $physical ${mtu}table $id $realm" );
	    emit( qq(echo "\$IP route del default via $gateway src $address dev $physical ${mtu}table $id $realm > /dev/null 2>&1"  >> \${VARDIR}/undo_${table}_routing) );
	}

	if ( ! $noautosrc ) {
	    if ( $shared ) {
		emit  "qt \$IP -$family rule del from $address";
		emit( "run_ip rule add from $address pref 20000 table $id" ,
		      "echo \"\$IP -$family rule del from $address pref 20000> /dev/null 2>&1\" >> \${VARDIR}/undo_${table}_routing" );
	    } else {
		emit  ( '',
			"find_interface_addresses $physical | while read address; do",
			"    qt \$IP -$family rule del from \$address",
			"    run_ip rule add from \$address pref 20000 table $id",
			"    echo \"\$IP -$family rule del from \$address pref 20000 > /dev/null 2>&1\" >> \${VARDIR}/undo_${table}_routing",
			'    rulenum=$(($rulenum + 1))',
			'done'
		      );
	    }
	}

	if ( @{$providerref->{persistent_routes}} ) {
	    emit '';
	    emit $_ for @{$providers{$table}->{persistent_routes}};
	}

	if ( @{$providerref->{persistent_rules}} ) {
	    emit '';
	    emit $_ for @{$providers{$table}->{persistent_rules}};
	}

	pop_indent;

	emit( qq(fi\n),
	      qq(echo 1 > \${VARDIR}/${physical}_disabled) );

	pop_indent;

	emit( "}\n" );
    }

    if ( $shared ) {
	my $variable = $providers{$table}{mac} = get_interface_mac( $gateway, $interface , $table, $mac );
	$realm = "realm $number";
	start_provider( $label , $table, $number, $id, qq(if interface_is_usable $physical && [ -n "$variable" ]; then) );
    } elsif ( $pseudo ) {
	start_provider( $label , $table, $number, $id, qq(if [ -n "\$SW_${base}_IS_USABLE" ]; then) );
    } else {
	if ( $optional ) {
	    start_provider( $label, $table , $number, $id, qq(if [ -n "\$SW_${base}_IS_USABLE" ]; then) );
	} elsif ( $gatewaycase eq 'detect' ) {
	    start_provider( $label, $table, $number, $id, qq(if interface_is_usable $physical && [ -n "$gateway" ]; then) );
	} else {
	    start_provider( $label, $table, $number, $id, "if interface_is_usable $physical; then" );
	}
	$provider_interfaces{$interface} = $table;

	if ( $gatewaycase eq 'omitted' ) {
	    if ( $tproxy ) {
		emit 'run_ip route add local ' . ALLIP . " dev $physical table $id";
	    } else {
		emit "run_ip route replace default dev $physical table $id";
	    }
	}
    }

    emit( "echo $load > \${VARDIR}/${table}_load",
	  'echo ' . in_hex( $mark ) . '/' . in_hex( $globals{PROVIDER_MASK} ) . " > \${VARDIR}/${table}_mark",
	  "echo $physical > \${VARDIR}/${table}_interface" ) if $load;

    emit( '',
	  "cat <<EOF >> \${VARDIR}/undo_${table}_routing" );

    emit_unindented 'case \$COMMAND in';
    emit_unindented '    enable|disable)';
    emit_unindented '        ;;';
    emit_unindented '    *)';
    emit_unindented "        rm -f \${VARDIR}/${physical}_load" if $load;
    emit_unindented "        rm -f \${VARDIR}/${physical}_mark" if $load;
    emit_unindented <<"CEOF", 1;
        rm -f \${VARDIR}/${physical}.status
        ;;
esac
EOF
CEOF
    #
    # /proc for this interface
    #
    setup_interface_proc( $interface );

    if ( $mark ne '-' ) {
	my $hexmark = in_hex( $mark );
	my $mask = have_capability( 'FWMARK_RT_MASK' ) ? '/' . in_hex( $globals{ $tproxy && ! $local ? 'TPROXY_MARK' : 'PROVIDER_MASK' } ) : '';

	emit ( "qt \$IP -$family rule del fwmark ${hexmark}${mask}" ) if $persistent || $config{DELETE_THEN_ADD};

	emit ( "run_ip rule add fwmark ${hexmark}${mask} pref $pref table $id",
	       "echo \"\$IP -$family rule del fwmark ${hexmark}${mask} > /dev/null 2>&1\" >> \${VARDIR}/undo_${table}_routing"
	    );
    }

    if ( $duplicate ne '-' ) {
	if ( $copy eq '-' ) {
	    copy_table ( $duplicate, $number, $realm );
	} else {
	    if ( $copy eq 'none' ) {
		$copy = $interface;
	    } else {
		$copy = "$interface,$copy";
	    }

	    copy_and_edit_table( $duplicate, $number, $id, $copy, $realm);
	}
    }

    if ( $gateway ) {
	$address = get_interface_address( $interface, 1 ) unless $address;

	if ( $hostroute ) {
	    emit qq(run_ip route replace $gateway src $address dev $physical ${mtu});
	    emit qq(run_ip route replace $gateway src $address dev $physical ${mtu}table $id $realm);
	}

	emit "run_ip route replace default via $gateway src $address dev $physical ${mtu}table $id $realm";
    }

    if ( $balance ) {
	balance_default_route( $balance , $gateway, $physical, $realm );
    } elsif ( $default > 0 ) {
	balance_fallback_route( $default , $gateway, $physical, $realm );
    } elsif ( $default ) {
	my $id = $providers{default}->{id};
	emit '';
	if ( $gateway ) {
	    emit qq(run_ip route replace $gateway/32 dev $physical table $id) if $hostroute;
	    emit qq(run_ip route replace default via $gateway src $address dev $physical table $id metric $number);
	    emit qq(echo "\$IP -$family route del default via $gateway table $id > /dev/null 2>&1" >> \${VARDIR}/undo_${table}_routing);
	    emit qq(echo "\$IP -4 route del $gateway/32 dev $physical table $id > /dev/null 2>&1" >> \${VARDIR}/undo_${table}_routing) if $family == F_IPV4;
	} else {
	    emit qq(run_ip route replace default table $id dev $physical metric $number);
	    emit qq(echo "\$IP -$family route del default dev $physical table $id > /dev/null 2>&1" >> \${VARDIR}/undo_${table}_routing);
	}

	emit( 'g_fallback=Yes' ) if $persistent;

	$metrics = 1;
    }

    emit( qq(\n) ,
	  qq(if ! \$IP -6 rule ls | egrep -q "32767:[[:space:]]+from all lookup (default|253)"; then) ,
	  qq(    qt \$IP -6 rule add from all table $providers{default}->{id} prio 32767\n) ,
	  qq(fi) ) if $family == F_IPV6;

    unless ( $tproxy ) {
	emit '';

	if ( $loose ) {
	    if ( $config{DELETE_THEN_ADD} ) {
		emit ( "find_interface_addresses $physical | while read address; do",
		       "    qt \$IP -$family rule del from \$address",
		       'done'
		     );
	    }
	} elsif ( ! $noautosrc ) {
	    if ( $shared ) {
		if ( $persistent ) {
		    emit( qq(if ! egrep -q "^20000:[[:space:]]+from $address lookup $id"; then),
			  qq(    qt \$IP -$family rule del from $address pref 20000),
			  qq(    run_ip rule add from $address pref 20000 table $id),
			  qq(    echo "\$IP -$family rule del from $address pref 20000> /dev/null 2>&1" >> \${VARDIR}/undo_${table}_routing ),
			  qq(fi) );
		} else {
		    emit  "qt \$IP -$family rule del from $address" if $persistent || $config{DELETE_THEN_ADD};
		    emit( "run_ip rule add from $address pref 20000 table $id" ,
			  "echo \"\$IP -$family rule del from $address pref 20000> /dev/null 2>&1\" >> \${VARDIR}/undo_${table}_routing" );
		}
	    } elsif ( ! $pseudo ) {
		emit  ( "find_interface_addresses $physical | while read address; do" );
		emit  ( "    qt \$IP -$family rule del from \$address" ) if $persistent || $config{DELETE_THEN_ADD};
		emit  ( "    run_ip rule add from \$address pref 20000 table $id",
			"    echo \"\$IP -$family rule del from \$address pref 20000 > /dev/null 2>&1\" >> \${VARDIR}/undo_${table}_routing",
			'    rulenum=$(($rulenum + 1))',
			'done'
		      );
	    }
	}
    }

    if ( @{$providerref->{rules}} ) {
	emit '';
	emit $_ for @{$providers{$table}->{rules}};
    }

    if ( @{$providerref->{routes}} ) {
	emit '';
	emit $_ for @{$providers{$table}->{routes}};
    }

    emit( '' );

    my ( $tbl, $weight );

    emit( qq(echo 0 > \${VARDIR}/${physical}.status) );

    if ( $optional ) {
	emit( '',
	      'if [ $COMMAND = enable ]; then' );

	push_indent;

	if ( $balance || $default > 0 ) {
	    $tbl    = $providers{$default ? 'default' : $config{USE_DEFAULT_RT} ? 'balance' : 'main'}->{id};
	    $weight = $balance ? $balance : $default;

	    if ( $gateway ) {
		emit qq(add_gateway "nexthop via $gateway dev $physical weight $weight $realm" ) . $tbl;
	    } else {
		emit qq(add_gateway "nexthop dev $physical weight $weight $realm" ) . $tbl;
	    }
	} else {
	    $weight = 1;
	}

	emit ( "distribute_load $maxload @load_providers" ) if $load;

	unless ( $shared ) {
	    emit( "setup_${dev}_tc" ) if $tcdevices->{$interface};
	}

	emit( qq(rm -f \${VARDIR}/${physical}_disabled),
	      $pseudo ? "run_enabled_exit ${physical} ${interface}" : "run_enabled_exit ${physical} ${interface} ${table}"
	    );

	if ( ! $pseudo && $config{USE_DEFAULT_RT} && $config{RESTORE_DEFAULT_ROUTE} ) {
	    emit  ( '#',
		    '# We now have a viable default route in the \'default\' table so delete any default routes in the main table',
		    '#',
		    'while qt \$IP -$family route del default table ' . MAIN_TABLE . '; do',
		    '    true',
		    'done',
		    ''
		);
	}

	emit_started_message( '', 2, $pseudo, $table, $number );

	if ( get_interface_option( $interface, 'used_address_variable' ) || get_interface_option( $interface, 'used_gateway_variable' ) ) {
	    emit( '',
		  'if [ -n "$g_forcereload" ]; then',
		  "    progress_message2 \"The IP address or gateway of $physical has changed -- forcing reload of the ruleset\"",
		  '    COMMAND=reload',
		  '    detect_configuration',
		  '    define_firewall',
		  'fi' );
	}

	pop_indent;

	unless ( $pseudo ) {
	    emit( 'else' );
	    emit( qq(    echo $weight > \${VARDIR}/${physical}_weight) );
	    emit( qq(    rm -f \${VARDIR}/${physical}_disabled) ) if $persistent;
	    emit_started_message( '    ', '', $pseudo, $table, $number );
	}

	emit "fi\n";

	if ( get_interface_option( $interface, 'used_address_variable' ) ) {
	    my $variable = get_interface_address( $interface );

	    emit( "echo $variable > \${VARDIR}/${physical}.address" );
	}

	if ( get_interface_option( $interface, 'used_gateway_variable' ) ) {
	    my $variable = get_interface_gateway( $interface );
	    emit( qq(echo "$variable" > \${VARDIR}/${physical}.gateway\n) );
	}
    } else {
	emit( qq(progress_message "Provider $table ($number) Started") );
    }

    pop_indent;

    emit 'else';

    push_indent;

    emit( qq(echo 1 > \${VARDIR}/${physical}.status) );

    if ( $optional ) {
	if ( $persistent ) {
	    emit( "do_persistent_${what}_${table}\n" );
	}

	if ( $shared ) {
	    emit ( "error_message \"WARNING: Gateway $gateway is not reachable -- Provider $table ($number) not Started\"" );
	} elsif ( $pseudo ) {
	    emit ( "error_message \"WARNING: Optional Interface $physical is not usable -- $table not Started\"" );
	} else {
	    emit ( "error_message \"WARNING: Interface $physical is not usable -- Provider $table ($number) not Started\"" );
	}


	if ( get_interface_option( $interface, 'used_address_variable' ) ) {
	    my $variable = interface_address( $interface );
	    emit( "\necho \$$variable > \${VARDIR}/${physical}.address" );
	}

	if ( get_interface_option( $interface, 'used_gateway_variable' ) ) {
	    my $variable = interface_gateway( $interface );
	    emit( qq(\necho "\$$variable" > \${VARDIR}/${physical}.gateway) );
	}
    } else {
	if ( $shared ) {
	    emit( "fatal_error \"Gateway $gateway is not reachable -- Provider $table ($number) Cannot be Started\"" );
	} else {
	    emit( "fatal_error \"Interface $physical is not usable -- Provider $table ($number) Cannot be Started\"" );
	}
    }

    pop_indent;

    emit 'fi';

    pop_indent;

    emit "} # End of start_${what}_${table}();";

    if ( $optional ) {
	emit( '',
	      '#',
	      "# Stop $what $table",
	      '#',
	      "stop_${what}_${table}() {" );

	push_indent;

	my $undo = "\${VARDIR}/undo_${table}_routing";

	emit( "if [ -f $undo ]; then" );

	push_indent;

	if ( $balance || $default > 0 ) {
	    $tbl    = $providers{$default ? 'default' : $config{USE_DEFAULT_RT} ? 'balance' : 'main'}->{id};
	    $weight = $balance ? $balance : $default;

	    my $via;

	    if ( $gateway ) {
		$via = "via $gateway dev $physical";
	    } else {
		$via = "dev $physical";
	    }

	    $via .= " weight $weight" unless $weight < 0;
	    $via .= " $realm"         if $realm;

	    emit( qq(delete_gateway "$via" $tbl $physical) );
	}

	emit (". $undo" );

	if ( $pseudo ) {
	    emit( "rm -f $undo" );
	} else {
	    emit( "> $undo" );
	}

	emit ( '',
	       "distribute_load $maxload @load_providers" ) if $load;

	if ( $persistent ) {
	    emit ( '',
		   'if [ $COMMAND = disable ]; then',
		   "    do_persistent_${what}_${table}",
		   "else",
		   "    echo 1 > \${VARDIR}/${physical}_disabled",
		   "fi\n",
		 );
	}

	unless ( $shared ) {
	    emit( '',
		  "qt \$TC qdisc del dev $physical root",
		  "qt \$TC qdisc del dev $physical ingress\n" ) if $tcdevices->{$interface};
	}

	emit( "echo 1 > \${VARDIR}/${physical}.status",
	      $pseudo ? "run_disabled_exit ${physical} ${interface}" : "run_disabled_exit ${physical} ${interface} ${table}"
	    );

	if ( $pseudo ) {
	    emit( "progress_message2 \"Optional Interface $table stopped\"" );
	} else {
	    emit( "progress_message2 \"Provider $table ($number) stopped\"" );
	}

	pop_indent;

	emit( 'else',
	      "    startup_error \"$undo does not exist\"",
	      'fi'
	    );

	pop_indent;

	emit '}';
    }
}
```

## add_an_rtrule1 (lines 1326–1422)

> adds a single routing rule to a provider

```perl
sub add_an_rtrule1( $$$$$ ) {
    my ( $source, $dest, $provider, $priority, $originalmark ) = @_;

    our $current_if;

    unless ( $providers{$provider} ) {
	my $found = 0;

	if ( "\L$provider" =~ /^(0x[a-f0-9]+|0[0-7]*|[0-9]*)$/ ) {
	    my $provider_number = numeric_value $provider;

	    for ( keys %providers ) {
		if ( $providers{$_}{number} == $provider_number ) {
		    $provider = $_;
		    $found = 1;
		    last;
		}
	    }
	}

	fatal_error "Unknown provider ($provider)" unless $found;
    }

    my $providerref = $providers{$provider};

    my $number = $providerref->{number};
    my $id     = $providerref->{id};

    fatal_error "You may not add rules for the $provider provider" if $number == LOCAL_TABLE || $number == UNSPEC_TABLE;
    fatal_error "You must specify either the source or destination in a rtrules entry" if $source eq '-' && $dest eq '-';

    if ( $dest eq '-' ) {
	$dest = 'to ' . ALLIP;
    } else {
	$dest = validate_net( $dest, 0 );
	$dest = "to $dest";
    }

    if ( $source eq '-' ) {
	$source = 'from ' . ALLIP;
    } elsif ( $source =~ s/^&// ) {
	$source = 'from ' . record_runtime_address( '&', $source, undef, 1 );
    } elsif ( $family == F_IPV4 ) {
	if ( $source =~ /:/ ) {
	    ( my $interface, $source , my $remainder ) = split( /:/, $source, 3 );
	    fatal_error "Invalid SOURCE" if defined $remainder;
	    $source = validate_net ( $source, 0 );
	    $interface = physical_name $interface;
	    $source = "iif $interface from $source";
	} elsif ( $source =~ /\..*\..*/ ) {
	    $source = validate_net ( $source, 0 );
	    $source = "from $source";
	} else {
	    $source = 'iif ' . physical_name $source;
	}
    } elsif ( $source =~  /^(.+?):<(.+)>\s*$/ ||  $source =~  /^(.+?):\[(.+)\]\s*$/ || $source =~ /^(.+?):(\[.+?\](?:\/\d+))$/ ) {
	my ($interface, $source ) = ($1, $2);
	$source = validate_net ($source, 0);
	$interface = physical_name $interface;
	$source = "iif $interface from $source";
    } elsif (  $source =~ /:.*:/ || $source =~ /\..*\..*/ ) {
	$source = validate_net ( $source, 0 );
	$source = "from $source";
    } else {
	$source = 'iif ' . physical_name $source;
    }

    my $mark = '';
    my $mask;

    if ( $originalmark ne '-' ) {
	validate_mark( $originalmark );

	( $mark, $mask ) = split '/' , $originalmark;
	$mask = $globals{PROVIDER_MASK} unless supplied $mask;

	$mark = ' fwmark ' . in_hex( $mark ) . '/' . in_hex( $mask );
    }

    my $persistent = ( $priority =~s/!$// );

    fatal_error "Invalid priority ($priority)" unless $priority && $priority =~ /^\d{1,5}$/;

    $priority = "pref $priority";

    push @{$providerref->{rules}}, "qt \$IP -$family rule del $source ${dest}${mark} $priority" if $persistent || $config{DELETE_THEN_ADD};
    push @{$providerref->{rules}}, "run_ip rule add $source ${dest}${mark} $priority table $id";

    if ( $persistent ) {
	push @{$providerref->{persistent_rules}}, "qt \$IP -$family rule del $source ${dest}${mark} $priority";
	push @{$providerref->{persistent_rules}}, "run_ip rule add $source ${dest}${mark} $priority table $id";
    }

    push @{$providerref->{rules}}, "echo \"\$IP -$family rule del $source ${dest}${mark} $priority > /dev/null 2>&1\" >> \${VARDIR}/undo_${provider}_routing";

    progress_message "   Routing rule \"$currentline\" $done";
}
```

## add_an_rtrule (lines 1424–1433)

> rtrules file row dispatcher

```perl
sub add_an_rtrule( ) {
    my ( $sources, $dests, $provider, $priority, $originalmark ) =
	split_line( 'rtrules file',
		    { source => 0, dest => 1, provider => 2, priority => 3 , mark => 4 } );
    for my $source ( split_list( $sources, "source" ) ) {
	for my $dest (split_list( $dests , "dest" ) ) {
	    add_an_rtrule1( $source, $dest, $provider, $priority, $originalmark );
	}
    }
}
```

## add_a_route (lines 1435–1529)

> routes file row dispatcher

```perl
sub add_a_route( ) {
    my ( $provider, $dest, $gateway, $device, $options ) =
	split_line( 'routes file',
		    { provider => 0, dest => 1, gateway => 2, device => 3, options=> 4 } );

    our $current_if;

    fatal_error 'PROVIDER must be specified' if $provider eq '-';

    unless ( $providers{$provider} ) {
	my $found = 0;

	if ( "\L$provider" =~ /^(0x[a-f0-9]+|0[0-7]*|[0-9]*)$/ ) {
	    my $provider_number = numeric_value $provider;

	    for ( keys %providers ) {
		if ( $providers{$_}{number} == $provider_number ) {
		    $provider = $_;
		    $found = 1;
		    last;
		}
	    }
	}

	fatal_error "Unknown provider ($provider)" unless $found;
    }

    fatal_error 'DEST must be specified' if $dest eq '-';
    $dest = validate_net ( $dest, 0 );

    my $null;

    if ( $gateway =~ /^(?:blackhole|unreachable|prohibit)$/ ) {
	fatal_error q('$gateway' routes may not specify a DEVICE) unless $device eq '-';
	$null = $gateway;
    } else {
	validate_address ( $gateway, 1 ) if $gateway ne '-';
    }

    my $providerref       = $providers{$provider};
    my $number            = $providerref->{number};
    my $id                = $providerref->{id};
    my $physical          = $device eq '-' ? $providers{$provider}{physical} : physical_name( $device );
    my $routes            = $providerref->{routes};
    my $persistent_routes = $providerref->{persistent_routes};
    my $routedests        = $providerref->{routedests};

    fatal_error "You may not add routes to the $provider table" if $number == LOCAL_TABLE || $number == UNSPEC_TABLE;

    $dest .= join( '', '/', VLSM ) unless $dest =~ '/';

    if ( $routedests->{$dest} ) {
	fatal_error "Duplicate DEST ($dest) in table ($provider)";
    } else {
	$routedests->{$dest} = 1;
    }

    my $persistent;

    if ( $options ne '-' ) {
	for ( split_list1( 'option', $options ) ) {
	    my ( $option, $value ) = split /=/, $options;

	    if ( $option eq 'persistent' ) {
		fatal_error "The 'persistent' option does not accept a value" if supplied $value;
		$persistent = 1;
	    } else {
		fatal_error "Invalid route option($option)";
	    }
	}
    }

    if ( $gateway ne '-' ) {
	if ( $device ne '-' ) {
	    push @$routes,            qq(run_ip route replace $dest via $gateway dev $physical table $id);
	    push @$persistent_routes, qq(run_ip route replace $dest via $gateway dev $physical table $id) if $persistent;
	    push @$routes,             q(echo "$IP ) . qq(-$family route del $dest via $gateway dev $physical table $id > /dev/null 2>&1" >> \${VARDIR}/undo_${provider}_routing) if $number >= DEFAULT_TABLE;
	} elsif ( $null ) {
	    push @$routes,            qq(run_ip route replace $null $dest table $id);
	    push @$persistent_routes, qq(run_ip route replace $null $dest table $id) if $persistent;
	    push @$routes,             q(echo "$IP ) . qq(-$family route del $null $dest table $id > /dev/null 2>&1" >> \${VARDIR}/undo_${provider}_routing) if $number >= DEFAULT_TABLE;
	} else {
	    push @$routes,            qq(run_ip route replace $dest via $gateway table $id);
	    push @$persistent_routes, qq(run_ip route replace $dest via $gateway table $id) if $persistent;
	    push @$routes,             q(echo "$IP ) . qq(-$family route del $dest via $gateway table $id > /dev/null 2>&1" >> \${VARDIR}/undo_${provider}_routing) if $number >= DEFAULT_TABLE;
	}
    } else {
	fatal_error "You must specify a device for this route" unless $physical;
	push @$routes,            qq(run_ip route replace $dest dev $physical table $id);
	push @$persistent_routes, qq(run_ip route replace $dest dev $physical table $id) if $persistent;
	push @$routes,             q(echo "$IP ) . qq(-$family route del $dest dev $physical table $id > /dev/null 2>&1" >> \${VARDIR}/undo_${provider}_routing) if $number >= DEFAULT_TABLE;
    }

    progress_message "   Route \"$currentline\" $done";
}
```

## process_providers (lines 1712–1885)

> reads providers/rtrules/routes files; calls add_a_provider for each

```perl
sub process_providers( $ ) {
    my $tcdevices = shift;

    our $providers = 0;
    our $pseudoproviders = 0;
    #
    # We defer initialization of the 'id' member until now so that the setting of USE_RT_NAMES will have been established.
    #
    unless ( $config{USE_RT_NAMES} ) {
	for ( values %providers ) {
	    $_->{id} = $_->{number};
	}
    } else {
	for ( values %providers ) {
	    $_->{id} = $_->{provider};
	}
    }

    $lastmark = 0;

    if ( my $fn = open_file 'providers' ) {
	first_entry "$doing $fn...";
	$providers += process_a_provider(0) while read_a_line( NORMAL_READ );
    }
    #
    # Treat optional interfaces as pseudo-providers
    #
    my $num = -65536;

    for ( grep interface_is_optional( $_ ) && ! $provider_interfaces{ $_ }, all_real_interfaces ) {
	$num++;
	#
	#               TABLE             NUMBER            MARK DUPLICATE INTERFACE GATEWAY OPTIONS COPY
	$currentline =  var_base($_) .  " $num              -    -         $_        -       -       -";
	#
	$pseudoproviders += process_a_provider(1);
    }

    if ( $providers ) {
	fatal_error q(Either all 'fallback' providers must specify a weight or none of them can specify a weight) if $fallback && $metrics;

	my $fn = open_file( 'route_rules' );

	if ( $fn ){
	    if ( -f ( my $fn1 = find_file 'rtrules' ) ) {
		warning_message "Both $fn and $fn1 exist: $fn1 will be ignored";
	    }
	} else {
	    $fn = open_file( 'rtrules' );
	}

	if ( $fn ) {
	    first_entry "$doing $fn...";

	    emit '';

	    add_an_rtrule while read_a_line( NORMAL_READ );
	}
    }

    my $fn = open_file 'routes';

    if ( $fn ) {
	first_entry "$doing $fn...";
	emit '';
	add_a_route while read_a_line( NORMAL_READ );
    }

    add_a_provider( $providers{$_}, $tcdevices ) for @providers;

    emithd << 'EOF';;

#
# Enable an optional provider
#
enable_provider() {
    g_interface=$1;

    case $g_interface in
EOF

    push_indent;
    push_indent;

    for my $provider (@providers ) {
	my $providerref = $providers{$provider};

	if ( $providerref->{optional} ) {
	    if ( $providerref->{shared} || $providerref->{physical} eq $provider) {
		emit "$provider)";
	    } else {
		emit( "$providerref->{physical}|$provider)" );
	    }

	    if ( $providerref->{pseudo} ) {
		emit ( "    if [ ! -f \${VARDIR}/undo_${provider}_routing ]; then",
		       "        start_interface_$provider" );
	    } elsif ( $providerref->{persistent} ) {
		emit ( "    if [ -f \${VARDIR}/$providerref->{physical}_disabled ]; then",
		       "        start_provider_$provider" );
	    } else {
		emit ( "    if [ -z \"`\$IP -$family route ls table $providerref->{number}`\" ]; then",
		       "        start_provider_$provider" );
	    }

	    emit ( '    elif [ -z "$2" ]; then',
		   "        startup_error \"Interface $providerref->{physical} is already enabled\"",
		   '    fi',
		   '    ;;'
		 );
	}
    }

    pop_indent;
    pop_indent;

    emithd << 'EOF';;
        *)
            startup_error "$g_interface is not an optional provider or interface"
            ;;
    esac
}

#
# Disable an optional provider
#
disable_provider() {
    g_interface=$1;

    case $g_interface in
EOF

    push_indent;
    push_indent;

    for my $provider (@providers ) {
	my $providerref = $providers{$provider};

	if ( $providerref->{optional} ) {
	    if ( $provider eq $providerref->{physical} ) {
		emit( "$provider)" );
	    } else {
		emit( "$providerref->{physical}|$provider)" );
	    }

	    if ( $providerref->{pseudo} ) {
		emit( "    if [ -f \${VARDIR}/undo_${provider}_routing ]; then" );
	    } elsif ( $providerref->{persistent} ) {
		emit( "    if [ ! -f \${VARDIR}/$providerref->{physical}_disabled ]; then" );
	    } else {
		emit( "    if [ -n \"`\$IP -$family route ls table $providerref->{number}`\" ]; then" );
	    }

	    emit( "        stop_$providerref->{what}_$provider",
		  '    elif [ -z "$2" ]; then',
		  "        startup_error \"Interface $providerref->{physical} is already disabled\"",
		  '    fi',
		  '    ;;'
		);
	}
    }

    pop_indent;
    pop_indent;

    emit << 'EOF';;
        *)
            startup_error "$g_interface is not an optional provider interface"
            ;;
    esac
}
EOF

}
```

## setup_providers (lines 1920–1989)

> orchestrator

```perl
sub setup_providers() {
    our $providers;
    our $pseudoproviders;

    if ( $providers ) {
	if ( $maxload ) {
	    warning_message "The sum of the provider interface loads exceeds 1.000000" if $maxload > 1;
	    warning_message "The sum of the provider interface loads is less than 1.000000" if $maxload < 1;
	}

	emit "\nif [ -z \"\$g_noroutes\" ]; then";

	push_indent;

	start_providers;

	setup_null_routing, emit '' if $config{NULL_ROUTE_RFC1918};

	if ( @providers ) {
	    emit "start_$providers{$_}->{what}_$_" for @providers;
	    emit '';
	}

	finish_providers;

	emit "\nrun_ip route flush cache";

	pop_indent;
	emit 'fi';

	setup_route_marking if @routemarked_interfaces || @load_providers;
    } else {
	emit "\nif [ -z \"\$g_noroutes\" ]; then";

	push_indent;

	emit "undo_routing";
	emit "restore_default_route $config{USE_DEFAULT_RT}";

	if ( $pseudoproviders ) {
	    emit '';
	    emit "start_$providers{$_}->{what}_$_" for @providers;
	}

	my $standard_routes = @{$providers{main}{routes}} || @{$providers{default}{routes}};

	if ( $config{NULL_ROUTE_RFC1918} ) {
	    emit '';
	    setup_null_routing;
	    emit "\nrun_ip route flush cache" unless $standard_routes;
	}

	if ( $standard_routes ) {
	    for my $provider ( qw/main default/ ) {
		emit '';
		emit qq(> \${VARDIR}/undo_${provider}_routing );
		emit '';
		emit $_ for @{$providers{$provider}{routes}};
		emit '';
		emit $_ for @{$providers{$provider}{rules}};
	    }

	    emit "\nrun_ip route flush cache";
	}

	pop_indent;

	emit 'fi';
    }
}
```
