# Tc.pm — extracted functions

**Source**: `Shorewall/Perl/Shorewall/Tc.pm`
**Git tag**: 5.2.6.1
**Purpose**: Reference for shorewall-nft Phase 6 work-package agents.

## Index

- `process_simple_device` (lines 257–385): Simple TC: builds TBF+prio tree
- `process_tc_priority1` (lines 1642–1689): tcpri file row worker
- `process_tc_priority` (lines 1691–1711): tcpri file row dispatcher
- `process_tcinterfaces` (lines 1716–1724): tcinterfaces file orchestrator
- `process_tcpri` (lines 1729–1761): tcpri file orchestrator
- `process_traffic_shaping` (lines 1766–2037): HTB/HFSC class+qdisc emitter
- `process_secmark_rule1` (lines 2075–2136): secmarks file row worker
- `process_secmark_rule` (lines 2141–2151): secmarks file row dispatcher

## process_simple_device (lines 257–385)

> Simple TC: builds TBF+prio tree

```perl
sub process_simple_device() {
    my ( $device , $type , $in_rate , $out_part ) =
	split_line( 'tcinterfaces',
		    { interface => 0, type => 1, in_bandwidth => 2, out_bandwidth => 3 } );

    fatal_error 'INTERFACE must be specified'      if $device eq '-';
    fatal_error "Duplicate INTERFACE ($device)"    if $tcdevices{$device};
    fatal_error "Invalid INTERFACE name ($device)" if $device =~ /[:+]/;

    my $number = in_hexp( $tcdevices{$device} = ++$devnum );

    fatal_error "Unknown interface( $device )" unless known_interface $device;

    my $physical = physical_name $device;
    my $dev      = var_base( $physical );

    push @tcdevices, $device;

    if ( $type ne '-' ) {
	if ( lc $type eq 'external' ) {
	    $type = 'nfct-src';
	} elsif ( lc $type eq 'internal' ) {
	    $type = 'dst';
	} else {
	    fatal_error "Invalid TYPE ($type)";
	}
    }

    $in_rate = process_in_bandwidth( $in_rate );


    emit( '',
	  '#',
	  "# Setup Simple Traffic Shaping for $physical",
	  '#',
	  "setup_${dev}_tc() {"
	);

    push_indent;

    emit "if interface_is_up $physical; then";

    push_indent;

    emit ( "qt \$TC qdisc del dev $physical root",
	   "qt \$TC qdisc del dev $physical ingress\n"
	 );

    handle_in_bandwidth( $physical, '', $in_rate );

    if ( $out_part ne '-' ) {
	my ( $out_bandwidth, $burst, $latency, $peak, $minburst ) = split ':', $out_part;

	fatal_error "Invalid Out-BANDWIDTH ($out_part)" if ( defined $minburst && $minburst =~ /:/ ) || $out_bandwidth eq '';

	$out_bandwidth = rate_to_kbit( $out_bandwidth );

	my $command = "run_tc qdisc add dev $physical root handle $number: tbf rate ${out_bandwidth}kbit";

	if ( supplied $burst ) {
	    fatal_error "Invalid burst ($burst)" unless $burst =~ /^\d+(?:\.\d+)?(k|kb|m|mb|mbit|kbit|b)?$/;
	    $command .= " burst $burst";
	} else {
	    $command .= ' burst 10kb';
	}

	if ( supplied $latency ) {
	    fatal_error "Invalid latency ($latency)" unless $latency =~ /^\d+(?:\.\d+)?(s|sec|secs|ms|msec|msecs|us|usec|usecs)?$/;
	    $command .= " latency $latency";
	} else {
	    $command .= ' latency 200ms';
	}

	$command .= ' mpu 64'; #Assume Ethernet

	if ( supplied $peak ) {
	    fatal_error "Invalid peak ($peak)" unless $peak =~ /^\d+(?:\.\d+)?(k|kb|m|mb|mbit|kbit|b)?$/;
	    $command .= " peakrate $peak";
	}

	if ( supplied $minburst ) {
	    fatal_error "Invalid minburst ($minburst)" unless $minburst =~ /^\d+(?:\.\d+)?(k|kb|m|mb|mbit|kbit|b)?$/;
	    $command .= " minburst $minburst";
	}

	emit $command;

	my $id = $number; $number = in_hexp( $devnum | 0x100 );

	emit "run_tc qdisc add dev $physical parent $id: handle $number: prio bands 3 priomap $config{TC_PRIOMAP}";
    } else {
	emit "run_tc qdisc add dev $physical root handle $number: prio bands 3 priomap $config{TC_PRIOMAP}";
    }

    for ( my $i = 1; $i <= 3; $i++ ) {
	my $prio = 16 | $i;
	my $j    = $i + 3;
	emit "run_tc qdisc add dev $physical parent $number:$i handle ${number}${i}: sfq quantum 1875 limit 127 perturb 10";
	emit "run_tc filter add dev $physical protocol all prio $prio parent $number: handle $i fw classid $number:$i";
	emit "run_tc filter add dev $physical protocol all prio 1 parent ${number}$i: handle $j flow hash keys $type divisor 1024" if $type ne '-' && have_capability 'FLOW_FILTER';
	emit '';
    }

    emit( "run_tc filter add dev $physical parent $number:0 protocol all prio 1 u32" .
	  "\\\n    match ip protocol 6 0xff" .
	  "\\\n    match u8 0x05 0x0f at 0" .
	  "\\\n    match u16 0x0000 0xffc0 at 2" .
	  "\\\n    match u8 0x10 0xff at 33 flowid $number:1\n" );

    emit( "run_tc filter add dev $physical parent $number:0 protocol all prio 1 u32" .
	  "\\\n    match ip6 protocol 6 0xff" .
	  "\\\n    match u8 0x05 0x0f at 0" .
	  "\\\n    match u16 0x0000 0xffc0 at 2" .
	  "\\\n    match u8 0x10 0xff at 33 flowid $number:1\n" );

    save_progress_message_short qq("   TC Device $physical defined.");

    pop_indent;
    emit 'else';
    push_indent;

    emit qq(error_message "WARNING: Device $physical is not in the UP state -- traffic-shaping configuration skipped");
    pop_indent;
    emit 'fi';
    pop_indent;
    emit "}\n";

    progress_message "  Simple tcdevice \"$currentline\" $done.";
}
```

## process_tc_priority1 (lines 1642–1689)

> tcpri file row worker

```perl
sub process_tc_priority1( $$$$$$ ) {
    my ( $band, $proto, $ports , $address, $interface, $helper ) = @_;

    my $val = numeric_value $band;

    fatal_error "Invalid PRIORITY ($band)" unless $val && $val <= 3;

    my $rule = do_helper( $helper ) . "-j MARK --set-mark $band";

    $rule .= join('', '/', in_hex( $globals{TC_MASK} ) ) if have_capability( 'EXMARK' );

    if ( $interface ne '-' ) {
	fatal_error "Invalid combination of columns" unless $address eq '-' && $proto eq '-' && $ports eq '-';

	my $forwardref = $mangle_table->{tcfor};

	add_rule( $forwardref ,
		  join( '', match_source_dev( $interface) , $rule ) ,
		  1 );
    } else {
	my $postref = $mangle_table->{tcpost};

	if ( $address ne '-' ) {
	    fatal_error "Invalid combination of columns" unless $proto eq '-' && $ports eq '-';
	    add_rule( $postref ,
		      join( '', match_source_net( $address) , $rule ) ,
		      1 );
	} else {
	    add_rule( $postref ,
		      join( '', do_proto( $proto, $ports, '-' , 0 ) , $rule ) ,
		      1 );

	    if ( $ports ne '-' ) {
		my $protocol = resolve_proto $proto;

		if ( $proto =~ /^ipp2p/ ) {
		    fatal_error "ipp2p may not be used when there are tracked providers and PROVIDER_OFFSET=0" if @routemarked_interfaces && $config{PROVIDER_OFFSET} == 0;
		    $ipp2p = 1;
		}

		add_rule( $postref ,
			  join( '' , do_proto( $proto, '-', $ports, 0 ) , $rule ) ,
			  1 )
		    unless $proto =~ /^ipp2p/ || $protocol == ICMP || $protocol == IPv6_ICMP;
	    }
	}
    }
}
```

## process_tc_priority (lines 1691–1711)

> tcpri file row dispatcher

```perl
sub process_tc_priority() {
    my ( $band, $protos, $ports , $address, $interface, $helper ) =
	split_line1( 'tcpri',
		     { band => 0, proto => 1, port => 2, address => 3, interface => 4, helper => 5 } );

    fatal_error 'BAND must be specified' if $band eq '-';

    fatal_error "Invalid tcpri entry" if ( $protos    eq '-' &&
					   $ports     eq '-' &&
					   $address   eq '-' &&
					   $interface eq '-' &&
					   $helper    eq '-' );

    my $val = numeric_value $band;

    fatal_error "Invalid PRIORITY ($band)" unless $val && $val <= 3;

    for my $proto ( split_list $protos, 'Protocol' ) {
	process_tc_priority1( $band, $proto, $ports , $address, $interface, $helper );
    }
}
```

## process_tcinterfaces (lines 1716–1724)

> tcinterfaces file orchestrator

```perl
#
# Process tcinterfaces
#
sub process_tcinterfaces() {

    my $fn = open_file 'tcinterfaces';

    if ( $fn ) {
	first_entry "$doing $fn...";
	process_simple_device while read_a_line( NORMAL_READ );
    }
}
```

## process_tcpri (lines 1729–1761)

> tcpri file orchestrator

```perl
#
# Process tcpri
#
sub process_tcpri() {
    my $fn  = find_file 'tcinterfaces';
    my $fn1 = open_file 'tcpri', 1,1;

    if ( $fn1 ) {
	first_entry
	    sub {
		progress_message2 "$doing $fn1...";
		warning_message "There are entries in $fn1 but $fn was empty" unless @tcdevices || $family == F_IPV6;
	    };

	process_tc_priority while read_a_line( NORMAL_READ );

	if ( $ipp2p ) {
	    insert_irule( $mangle_table->{tcpost} ,
			  j => 'CONNMARK --restore-mark --ctmask ' . in_hex( $globals{TC_MASK} ) ,
			  0 ,
			  mark => '--mark 0/'   . in_hex( $globals{TC_MASK} )
			);

	    insert_irule( $mangle_table->{tcpost} ,
			  j => 'RETURN', 
			  1 ,
			  mark => '! --mark 0/' . in_hex( $globals{TC_MASK} ) ,
			);

	    add_ijump( $mangle_table->{tcpost} ,
		       j    => 'CONNMARK --save-mark --mask '    . in_hex( $globals{TC_MASK} ),
		       mark => '! --mark 0/' . in_hex( $globals{TC_MASK} )
		     );
	}
    }
}
```

## process_traffic_shaping (lines 1766–2037)

> HTB/HFSC class+qdisc emitter

```perl
sub process_traffic_shaping() {

    our $lastrule = '';

    my $fn = open_file 'tcdevices';

    if ( $fn ) {
	first_entry "$doing $fn...";

	validate_tc_device while read_a_line( NORMAL_READ );
    }

    $devnum = $devnum > 10 ? 10 : 1;

    $fn = open_file 'tcclasses';

    if ( $fn ) {
	first_entry "$doing $fn...";

	validate_tc_class while read_a_line( NORMAL_READ );
    }

    process_tcfilters;

    my $sfq = 0;
    my $sfqinhex;

    for my $devname ( @tcdevices ) {
	my $devref  = $tcdevices{$devname};
	my $defmark = in_hexp ( $devref->{default} || 0 );
	my $devnum  = in_hexp $devref->{number};
	my $r2q     = int calculate_r2q $devref->{out_bandwidth};
	my $qdisc   = $devref->{qdisc};

	fatal_error "No default class defined for device $devname" unless defined $devref->{default};

	my $device = physical_name $devname;

	unless ( $config{TC_ENABLED} eq 'Shared' ) {

	    my $dev = var_base( $device );

	    emit( '',
		  '#',
		  "# Configure Traffic Shaping for $device",
		  '#',
		  "setup_${dev}_tc() {" );

	    push_indent;

	    emit "if interface_is_up $device; then";

	    push_indent;

	    emit ( "qt \$TC qdisc del dev $device root",
		   "qt \$TC qdisc del dev $device ingress" );

	    emit ( "${dev}_mtu=\$(get_device_mtu $device)",
		   "${dev}_mtu1=\$(get_device_mtu1 $device)"
		 ) if $qdisc eq 'htb';

	    my $stab;

	    if ( $devref->{linklayer} ) {
		$stab =  "stab linklayer $devref->{linklayer} overhead $devref->{overhead} ";
		$stab .= "mtu $devref->{mtu} "     if $devref->{mtu};
		$stab .= "mpu $devref->{mpu} "     if $devref->{mpu};
		$stab .= "tsize $devref->{tsize} " if $devref->{tsize};
	    } else {
		$stab = '';
	    }

	    if ( $qdisc eq 'htb' ) {
		emit ( "run_tc qdisc add dev $device ${stab}root handle $devnum: htb default $defmark r2q $r2q" ,
		       "run_tc class add dev $device parent $devnum: classid $devnum:1 htb rate $devref->{out_bandwidth} \$${dev}_mtu1" );
	    } else {
		emit ( "run_tc qdisc add dev $device ${stab}root handle $devnum: hfsc default $defmark" ,
		       "run_tc class add dev $device parent $devnum: classid $devnum:1 hfsc sc rate $devref->{out_bandwidth} ul rate $devref->{out_bandwidth}" );
	    }

	    if ( $devref->{occurs} ) {
		#
		# The following command may succeed yet generate an error message and non-zero exit status :-(. We thus run it silently
		# and check the result. Note that since this is the first filter added after the root qdisc was added, the 'ls | grep' test
		# is fairly robust
		#
		my $command = "\$TC filter add dev $device parent $devnum:0 prio 65535 protocol all fw";

		emit( qq(if ! qt $command ; then) ,
		      qq(    if ! \$TC filter list dev $device | grep -q 65535; then) ,
		      qq(        error_message "ERROR: Command '$command' failed"),
		      qq(        stop_firewall),
		      qq(        exit 1),
		      qq(    fi),
		      qq(fi) );
	    }

	    handle_in_bandwidth( $device, $stab, $devref->{in_bandwidth} );

	    for my $rdev ( @{$devref->{redirected}} ) {
		my $phyrdev = physical_name( $rdev );
		emit ( "run_tc qdisc add dev $phyrdev handle ffff: ingress" );
		emit( "run_tc filter add dev $phyrdev parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev $device > /dev/null" );
	    }

	    for my $class ( @tcclasses ) {
		#
		# The class number in the tcclasses array is expressed in decimal.
		#
		my ( $d, $decimalclassnum ) = split /:/, $class;

		next unless $d eq $devname;
		#
		# For inclusion in 'tc' commands, we also need the hex representation
		#
		my $classnum = in_hexp $decimalclassnum;
		#
		# The decimal value of the class number is also used as the key for the hash at $tcclasses{$device}
		#
		my $tcref    = $tcclasses{$devname}{$decimalclassnum};
		my $mark     = $tcref->{mark};
		my $devicenumber  = in_hexp $devref->{number};
		my $classid  = join( ':', $devicenumber, $classnum);
		my $rawrate  = $tcref->{rate};
		my $rate     = "${rawrate}kbit";
		my $lsceil   = $tcref->{lsceil};
		my $quantum;

		$classids{$classid}=$devname;

		my $parent   = in_hexp $tcref->{parent};

		if ( $devref->{qdisc} eq 'htb' ) {
		    $quantum  = calculate_quantum $rate, calculate_r2q( $devref->{out_bandwidth} );
		    emit ( "[ \$${dev}_mtu -gt $quantum ] && quantum=\$${dev}_mtu || quantum=$quantum" );
		    emit ( "run_tc class add dev $device parent $devicenumber:$parent classid $classid htb rate $rate ceil $tcref->{ceiling}kbit prio $tcref->{priority} \$${dev}_mtu1 quantum \$quantum" );
		} else {
		    my $dmax = $tcref->{dmax};
		    my $rule = "run_tc class add dev $device parent $devicenumber:$parent classid $classid hfsc";

		    if ( $dmax ) {
			my $umax = $tcref->{umax} ? "$tcref->{umax}b" : "\$(get_device_mtu $device)b";
			$rule .= " sc umax $umax dmax ${dmax}ms";
			$rule .= " rate $rate" if $rawrate;
		    } else {
			$rule .= " sc rate $rate" if $rawrate;
		    }

		    $rule .= " ls rate ${lsceil}kbit" if $lsceil;
		    $rule .= " ul rate $tcref->{ceiling}kbit" if $tcref->{ceiling};

		    emit $rule;
		}

		if ( $tcref->{leaf} ) {
		    if ( $tcref->{red} ) {
			1 while $devnums[++$sfq];
			$sfqinhex = in_hexp( $sfq);

			my ( $options, $redopts ) = ( '', $tcref->{redopts} );

			for my $option ( keys %validredoptions ) {
			    my $type = $validredoptions{$option};

			    if ( my $value = $redopts->{$option} ) {
				if ( $type == RED_NONE ) {
				    $options = join( ' ', $options, $option ) if $value;
				} else {
				    $options = join( ' ', $options, $option, $value );
				}
			    }
			}

			emit( "run_tc qdisc add dev $device parent $classid handle $sfqinhex: red${options}" );
		    } elsif ( $tcref->{fq_codel} ) {
			1 while $devnums[++$sfq];
			$sfqinhex = in_hexp( $sfq);

			my ( $options, $codelopts ) = ( '', $tcref->{codelopts} );

			for my $option ( keys %validcodeloptions ) {
			    my $type = $validcodeloptions{$option};

			    if ( my $value = $codelopts->{$option} ) {
				if ( $type == CODEL_NONE ) {
				    $options = join( ' ', $options, $option );
				} else {
				    $options = join( ' ', $options, $option, $value );
				}
			    }
			}

			emit( "run_tc qdisc add dev $device parent $classid handle $sfqinhex: fq_codel${options}" );
			
		    } elsif ( ! $tcref->{pfifo} ) {
			1 while $devnums[++$sfq];

			$sfqinhex = in_hexp( $sfq);
			if ( $qdisc eq 'htb' ) {
			    emit( "run_tc qdisc add dev $device parent $classid handle $sfqinhex: sfq quantum \$quantum limit $tcref->{limit} perturb 10" );
			} else {
			    emit( "run_tc qdisc add dev $device parent $classid handle $sfqinhex: sfq limit $tcref->{limit} perturb 10" );
			}
		    }
		}
		#
		# add filters
		#
		unless ( $mark eq '-' ) {
		    emit "run_tc filter add dev $device protocol all parent $devicenumber:0 prio $tcref->{markprio} handle $mark fw classid $classid" if $tcref->{occurs} == 1;
		}

		emit "run_tc filter add dev $device protocol all prio 1 parent $sfqinhex: handle $classnum flow hash keys $tcref->{flow} divisor 1024" if $tcref->{flow};
		#
		# options
		#
		emit( "run_tc filter add dev $device parent $devicenumber:0 protocol ip prio $tcref->{tcp_ack} u32" .
		      "\\\n    match ip protocol 6 0xff" .
		      "\\\n    match u8 0x05 0x0f at 0" .
		      "\\\n    match u16 0x0000 0xffc0 at 2" .
		      "\\\n    match u8 0x10 0xff at 33 flowid $classid" ) if $tcref->{tcp_ack};

		for my $tospair ( @{$tcref->{tos}} ) {
		    ( $tospair, my $priority ) = split /:/, $tospair;
		    my ( $tos, $mask ) = split q(/), $tospair;
		    emit "run_tc filter add dev $device parent $devicenumber:0 protocol ip prio $priority u32 match ip tos $tos $mask flowid $classid";
		}

		save_progress_message_short qq("   TC Class $classid defined.");
		emit '';

	    }

	    emit '';

	    emit "$_" for @{$devref->{filters}};

	    save_progress_message_short qq("   TC Device $device defined.");

	    pop_indent;
	    emit 'else';
	    push_indent;

	    emit qq(error_message "WARNING: Device $device is not in the UP state -- traffic-shaping configuration skipped");
	    pop_indent;
	    emit "fi\n";

	    pop_indent;
	    emit "}\n";
	} else {
	    for my $class ( @tcclasses ) {
		#
		# The class number in the tcclasses array is expressed in decimal.
		#
		my ( $d, $decimalclassnum ) = split /:/, $class;

		next unless $d eq $devname;
		#
		# For inclusion in 'tc' commands, we also need the hex representation
		#
		my $classnum = in_hexp $decimalclassnum;
		#
		# The decimal value of the class number is also used as the key for the hash at $tcclasses{$device}
		#
		my $devicenumber  = in_hexp $devref->{number};
		my $classid  = join( ':', $devicenumber, $classnum);

		$classids{$classid}=$devname;
	    }
	}
    }
}
```

## process_secmark_rule1 (lines 2075–2136)

> secmarks file row worker

```perl
sub process_secmark_rule1( $$$$$$$$$ ) {
    my ( $secmark, $chainin, $source, $dest, $proto, $dport, $sport, $user, $mark ) = @_;

    my %chns = ( T => 'tcpost'  ,
		 P => 'tcpre'   ,
		 F => 'tcfor'   ,
		 I => 'tcin'    ,
		 O => 'tcout'   , );

    my %state = ( N   => 'NEW' ,
		  I   => 'INVALID',
		  U   => 'UNTRACKED',
		  IU  => 'INVALID,UNTRACKED',
		  NI  => 'NEW,INVALID',
		  NU  => 'NEW,UNTRACKED',
		  NIU => 'NEW,INVALID,UNTRACKED',
		  E   => 'ESTABLISHED' ,
		  ER  => 'ESTABLISHED,RELATED',
		);

    my ( $chain , $state, $rest) = split ':', $chainin , 3;

    fatal_error "Invalid CHAIN:STATE ($chainin)" if $rest || ! $chain;

    my $chain1= $chns{$chain};

    fatal_error "Invalid or missing CHAIN ( $chain )" unless $chain1;
    fatal_error "USER/GROUP may only be used in the OUTPUT chain" if $user ne '-' && $chain1 ne 'tcout';

    if ( ( $state ||= '' ) ne '' ) {
	my $state1;
	fatal_error "Invalid STATE ( $state )" unless $state1 = $state{$state};
	$state = state_match( $state1 );
    }

    my $target = $secmark eq 'SAVE'    ? 'CONNSECMARK --save' :
	         $secmark eq 'RESTORE' ? 'CONNSECMARK --restore' :
		 "SECMARK --selctx $secmark";

    my $disposition = $target;

    $disposition =~ s/ .*//;

    expand_rule( ensure_mangle_chain( $chain1 ) ,
		 $restrictions{$chain1} ,
		 '' ,
		 $state .
		 do_proto( $proto, $dport, $sport ) .
		 do_user( $user ) .
		 do_test( $mark, $globals{TC_MASK} ) ,
		 $source ,
		 $dest ,
		 '' ,
		 $target ,
		 '' ,
		 $disposition,
		 '' ,
		 '' );

    progress_message "Secmarks rule \"$currentline\" $done";

}
```

## process_secmark_rule (lines 2141–2151)

> secmarks file row dispatcher

```perl
#
# Process a record in the secmarks file
#
sub process_secmark_rule() {
    my ( $secmark, $chainin, $source, $dest, $protos, $dport, $sport, $user, $mark ) =
	split_line1( 'Secmarks file' ,
		     { secmark => 0, chain => 1, source => 2, dest => 3, proto => 4, dport => 5, sport => 6, user => 7, mark => 8 } );

    fatal_error 'SECMARK must be specified' if $secmark eq '-';

    for my $proto ( split_list( $protos, 'Protocol' ) ) {
	process_secmark_rule1( $secmark, $chainin, $source, $dest, $proto, $dport, $sport, $user, $mark );
    }
}
```

## Note

`process_tc_rule` lives in **Rules.pm:5313** — see rules.md.
