# Misc.pm — extracted functions

**Source**: `Shorewall/Perl/Shorewall/Misc.pm`
**Git tag**: 5.2.6.1
**Purpose**: Reference for shorewall-nft Phase 6 work-package agents.

## Index

- `add_rule_pair` (lines 155–167): helper that logs + jumps
- `remove_blacklist` (lines 172–213): strips blacklist references from a file
- `convert_blacklist` (lines 218–410): converts pre-4.4.25 blacklist file to blrules format
- dynamic blacklist ipset setup block (lines 788–851): inside add_common_rules

## add_rule_pair (lines 155–167)

> helper that logs + jumps

```perl
sub add_rule_pair( $$$$$ ) {
    my ($chainref , $predicate , $target , $level, $tag ) = @_;

    log_rule_limit( $level,
		    $chainref,
		    $chainref->{name},
		    "\U$target",
		    $globals{LOGLIMIT},
		    $tag,
		    'add',
		    $predicate )  if supplied $level;
    add_jump( $chainref , $target, 0, $predicate );
}
```

## remove_blacklist (lines 172–213)

> strips blacklist references from a file

```perl
#
# Remove instances of 'blacklist' from the passed file.
#
sub remove_blacklist( $ ) {
    my $file = shift;

    my $fn = find_file $file;

    return 1 unless -f $file;

    my $oldfile = open_file $fn;
    my $newfile;
    my $changed;

    open $newfile, '>', "$fn.new" or fatal_error "Unable to open $fn.new for output: $!";

    while ( read_a_line( EMBEDDED_ENABLED | EXPAND_VARIABLES ) ) {
	my ( $rule, $comment ) = split '#', $currentline, 2;

	if ( $rule && $rule =~ /blacklist/ ) {
	    $changed = 1;

	    if ( $comment ) {
		$comment =~ s/^/          / while $rule =~ s/blacklist,// || $rule =~ s/,blacklist//;
		$rule =~ s/blacklist/         /g;
		$currentline = join( '#', $rule, $comment );
	    } else {
		$currentline =~ s/blacklist,//g;
		$currentline =~ s/,blacklist//g;
		$currentline =~ s/blacklist/         /g;
	    }
	}

	print $newfile "$currentline\n";
    }

    close $newfile;

    if ( $changed ) {
	rename $fn, "$fn.bak" or fatal_error "Unable to rename $fn to $fn.bak: $!";
	rename "$fn.new", $fn or fatal_error "Unable to rename $fn.new to $fn: $!";
	transfer_permissions( "$fn.bak", $fn );
	progress_message2 "\u$file file $fn saved in $fn.bak"
    }
}
```

## convert_blacklist (lines 218–410)

> converts pre-4.4.25 blacklist file to blrules format

```perl
#
# Convert a pre-4.4.25 blacklist to a 4.4.25 blrules file
#
sub convert_blacklist() {
    my $zones  = find_zones_by_option 'blacklist', 'in';
    my $zones1 = find_zones_by_option 'blacklist', 'out';
    my ( $level, $disposition ) = @config{'BLACKLIST_LOG_LEVEL', 'BLACKLIST_DISPOSITION' };
    my $tag         = $globals{MACLIST_LOG_TAG};
    my $audit       = $disposition =~ /^A_/;
    my $target      = $disposition;
    my $orig_target = $target;
    my $warnings    = 0;
    my @rules;

    if ( @$zones || @$zones1 ) {
	if ( supplied $level ) {
	    $target = supplied $tag ? "$target:$level:$tag":"$target:$level";
	}

	my $fn = open_file( 'blacklist' );

	unless ( $fn ) {
	    if ( -f ( $fn = find_file( 'blacklist' ) ) ) {
		if ( unlink( $fn ) ) {
		    warning_message "Empty blacklist file ($fn) removed";
		} else {
		    warning_message "Unable to remove empty blacklist file $fn: $!";
		}
	    }

	    return 0;
	}

	directive_callback(
	    sub ()
	    {
		warning_message "Omitted rules and compiler directives were not translated" unless $warnings++;
	    }
	    );

	first_entry "Converting $fn...";

	while ( read_a_line( NORMAL_READ ) ) {
	    my ( $networks, $protocol, $ports, $options ) =
		split_rawline2( 'blacklist file',
				{ networks => 0, proto => 1, port => 2, options => 3 },
				{},
				4,
		);

	    if ( $options eq '-' ) {
		$options = 'src';
	    } elsif ( $options eq 'audit' ) {
		$options = 'audit,src';
	    }

	    my ( $to, $from, $whitelist, $auditone ) = ( 0, 0, 0, 0 );

	    my @options = split_list $options, 'option';

	    for ( @options ) {
		$whitelist++ if $_ eq 'whitelist';
		$auditone++  if $_ eq 'audit';
	    }

	    warning_message "Duplicate 'whitelist' option ignored" if $whitelist > 1;

	    my $tgt = $whitelist ? 'WHITELIST' : $target;

	    if ( $auditone ) {
		fatal_error "'audit' not allowed in whitelist entries" if $whitelist;

		if ( $audit ) {
		    warning_message "Superfluous 'audit' option ignored";
		} else {
		    warning_message "Duplicate 'audit' option ignored" if $auditone > 1;
		}
	    }

	    for ( @options ) {
		if ( $_ =~ /^(?:src|from)$/ ) {
		    if ( $from++ ) {
			warning_message "Duplicate 'src' ignored";
		    } else {
			if ( @$zones ) {
			    push @rules, [ 'src', $tgt, $networks, $protocol, $ports ];
			} else {
			    warning_message '"src" entry ignored because there are no "blacklist in" zones';
			}
		    }
		} elsif ( $_ =~ /^(?:dst|to)$/ ) {
		    if ( $to++ ) {
			warning_message "Duplicate 'dst' ignored";
		    } else {
			if ( @$zones1 ) {
			    push @rules, [ 'dst', $tgt, $networks, $protocol, $ports ];
			} else {
			    warning_message '"dst" entry ignored because there are no "blacklist out" zones';
			}
		    }
		} else {
		    fatal_error "Invalid blacklist option($_)" unless $_ eq 'whitelist' || $_ eq 'audit';
		}
	    }
	}

	directive_callback(0);

	if ( @rules ) {
	    my $fn1 = find_writable_file( 'blrules' );
	    my $blrules;
	    my $date = compiletime;

	    if ( -f $fn1 ) {
		open $blrules, '>>', $fn1 or fatal_error "Unable to open $fn1: $!";
	    } else {
		open $blrules, '>',  $fn1 or fatal_error "Unable to open $fn1: $!";
		transfer_permissions( $fn, $fn1 );
		print $blrules <<'EOF';
#
# Shorewall - Blacklist Rules File
#
# For information about entries in this file, type "man shorewall-blrules"
#
# Please see https://shorewall.org/blacklisting_support.htm for additional
# information.
#
###################################################################################################################################################################################################
#ACTION		SOURCE		        DEST		        PROTO	DEST	SOURCE		ORIGINAL	RATE		USER/	MARK	CONNLIMIT	TIME         HEADERS         SWITCH
#							                PORT	PORT(S)		DEST		LIMIT		GROUP
EOF
	    }

	    print( $blrules
		   "#\n" ,
		   "# Rules generated from blacklist file $fn by Shorewall $globals{VERSION} - $date\n" ,
		   "#\n" );

	    for ( @rules ) {
		my ( $srcdst, $tgt, $networks, $protocols, $ports ) = @$_;

		$tgt .= "\t\t";

		my $list = $srcdst eq 'src' ? $zones : $zones1;

		for my $zone ( @$list ) {
		    my $rule = $tgt;

		    if ( $srcdst eq 'src' ) {
			if ( $networks ne '-' ) {
			    $rule .= "$zone:$networks\tall\t\t";
			} else {
			    $rule .= "$zone\t\t\tall\t\t";
			}
		    } else {
			if ( $networks ne '-' ) {
			    $rule .= "all\t\t\t$zone:$networks\t";
			} else {
			    $rule .= "all\t\t\t$zone\t\t\t";
			}
		    }

		    $rule .= "\t$protocols" if $protocols ne '-';
		    $rule .= "\t$ports"     if $ports     ne '-';

		    print $blrules "$rule\n";
		}
	    }

	    close $blrules;
	} else {
	    warning_message q(There are interfaces or zones with the 'blacklist' option but the 'blacklist' file is empty or does not exist) unless @rules;
	}

	if ( -f $fn ) {
	    rename $fn, "$fn.bak";
	    progress_message2 "Blacklist file $fn saved in $fn.bak";
	}

	for my $file ( qw(zones interfaces hosts) ) {
	    remove_blacklist $file;
	}

	progress_message2 "Blacklist successfully converted";

	return 1;
    } else {
	my $fn = find_file 'blacklist';
	if ( -f $fn ) {
	    rename $fn, "$fn.bak" or fatal_error "Unable to rename $fn to $fn.bak: $!";
	    warning_message "No zones have the blacklist option - the blacklist file was saved in $fn.bak";
	}

	return 0;
    }
}
```

## dynamic blacklist ipset setup block (lines 788–851)

> dynamic blacklist ipset setup inside add_common_rules

```perl
    if ( my $val = $config{DYNAMIC_BLACKLIST} ) {
	( $dbl_type, $dbl_ipset, $dbl_level, $dbl_tag ) = split( ':', $val );

	unless ( $dbl_type =~ /^ipset-only/ ) {
	    add_rule_pair( set_optflags( new_standard_chain( 'logdrop' )  , DONT_OPTIMIZE | DONT_DELETE ), '' , 'DROP'   , $level , $tag);
	    add_rule_pair( set_optflags( new_standard_chain( 'logreject' ), DONT_OPTIMIZE | DONT_DELETE ), '' , 'reject' , $level , $tag);
	    $dynamicref =  set_optflags( new_standard_chain( 'dynamic' ) ,  DONT_OPTIMIZE );
	    add_commands( $dynamicref, '[ -f ${VARDIR}/.dynamic ] && cat ${VARDIR}/.dynamic >&3' );
	}

	if ( $dbl_ipset ) {
	    if ( $val = $globals{DBL_TIMEOUT} ) {
		$dbl_options    = $globals{DBL_OPTIONS};
		$dbl_src_target = $dbl_options =~ /src-dst/ ? 'dbl_src' : 'dbl_log';

		my $chainref = new_standard_chain( $dbl_src_target );

		log_rule_limit( $dbl_level,
				$chainref,
				'dbl_log',
				'DROP',
				$globals{LOGLIMIT},
				$dbl_tag,
				'add',
				'',
				$origin{DYNAMIC_BLACKLIST} ) if $dbl_level;
		add_ijump_extended( $chainref, j => "SET --add-set $dbl_ipset src --exist --timeout $val", $origin{DYNAMIC_BLACKLIST} ) unless $dbl_options =~ /noupdate/;
		add_ijump_extended( $chainref, j => 'DROP', $origin{DYNAMIC_BLACKLIST} );

		if ( $dbl_src_target eq 'dbl_src' ) {
		    $chainref = new_standard_chain( $dbl_dst_target = 'dbl_dst' );

		    log_rule_limit( $dbl_level,
				    $chainref,
				    'dbl_log',
				    'DROP',
				    $globals{LOGLIMIT},
				    $dbl_tag,
				    'add',
				    '',
				    $origin{DYNAMIC_BLACKLIST} ) if $dbl_level;
		    add_ijump_extended( $chainref, j => "SET --add-set $dbl_ipset dst --exist --timeout $val", $origin{DYNAMIC_BLACKLIST} );
		    add_ijump_extended( $chainref, j => 'DROP', $origin{DYNAMIC_BLACKLIST} );
		} else {
		    $dbl_dst_target = $dbl_src_target;
		}		    
	    } elsif ( $dbl_level ) {
		my $chainref = new_standard_chain( $dbl_src_target = $dbl_dst_target = 'dbl_log' );

		log_rule_limit( $dbl_level,
				$chainref,
				'dbl_log',
				'DROP',
				$globals{LOGLIMIT},
				$dbl_tag,
				'add',
				'',
				$origin{DYNAMIC_BLACKLIST} );
		add_ijump_extended( $chainref, j => 'DROP', $origin{DYNAMIC_BLACKLIST} );
	    } else {
		$dbl_src_target = $dbl_dst_target = 'DROP'; 
	    }
	}
    }
```

## Note

`setup_blacklist` and `process_dynamic_blacklist` do not exist as standalone subs in 5.2.6.1; the dynamic blacklist initialization lives inline in `add_common_rules`.
