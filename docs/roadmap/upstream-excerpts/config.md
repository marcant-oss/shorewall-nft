# Config.pm — extracted blocks

**Source**: `Shorewall/Perl/Shorewall/Config.pm`
**Git tag**: 5.2.6.1
**Purpose**: Reference for shorewall-nft Phase 6 work-package agents.

## Index

- "Mark geometry initialization" — lines 5459–5468 and lines 6772–6815
- "Disposition defaults block" — lines 6826–6974 (excerpt)
- "Logging defaults block" — lines 6856–6877 and 7058–7078

## Mark geometry initialization

```perl
    my $wide = is_set $config{WIDE_TC_MARKS};
    my $high = is_set $config{HIGH_ROUTE_MARKS};

    #
    # Establish default values for the mark layout items
    #
    $config{TC_BITS}         = ( $wide ? 14 : 8 )             unless defined $config{TC_BITS};
    $config{MASK_BITS}       = ( $wide ? 16 : 8 )             unless defined $config{MASK_BITS};
    $config{PROVIDER_OFFSET} = ( $high ? $wide ? 16 : 8 : 0 ) unless defined $config{PROVIDER_OFFSET};
    $config{PROVIDER_BITS}   = 8                              unless defined $config{PROVIDER_BITS};
```

```perl
    numeric_option 'TC_BITS'         , 8, 0;
    numeric_option 'MASK_BITS'       , 8, 0;
    numeric_option 'PROVIDER_OFFSET' , 0, 0;
    numeric_option 'PROVIDER_BITS'   , 8, 0;
    numeric_option 'ZONE_BITS'       , 0, 0;

    require_capability 'MARK_ANYWHERE', 'A non-zero ZONE_BITS setting', 's' if $config{ZONE_BITS};

    if ( $config{PROVIDER_OFFSET} ) {
	$config{PROVIDER_OFFSET}  = $config{MASK_BITS} if $config{PROVIDER_OFFSET} < $config{MASK_BITS};
	$globals{ZONE_OFFSET}     = $config{PROVIDER_OFFSET} + $config{PROVIDER_BITS};
    } elsif ( $config{MASK_BITS} >= $config{PROVIDER_BITS} ) {
	$globals{ZONE_OFFSET}     = $config{MASK_BITS};
    } else {
	$globals{ZONE_OFFSET}     = $config{PROVIDER_BITS};
    }

    #
    # It is okay if the event mark is outside of the a 32-bit integer. We check that in IfEvent"
    #
    fatal_error 'Invalid Packet Mark layout' if $config{ZONE_BITS} + $globals{ZONE_OFFSET} > 30;

    $globals{EXCLUSION_MASK} = 1 << ( $globals{ZONE_OFFSET} + $config{ZONE_BITS} );
    $globals{TPROXY_MARK}    = $globals{EXCLUSION_MASK} << 1;
    $globals{EVENT_MARK}     = $globals{TPROXY_MARK} << 1;
    $globals{PROVIDER_MIN}   = 1 << $config{PROVIDER_OFFSET};

    $globals{TC_MAX}         = make_mask( $config{TC_BITS} );
    $globals{TC_MASK}        = make_mask( $config{MASK_BITS} );
    $globals{PROVIDER_MASK}  = make_mask( $config{PROVIDER_BITS} ) << $config{PROVIDER_OFFSET};

    if ( $config{ZONE_BITS} ) {
	$globals{ZONE_MASK} = make_mask( $config{ZONE_BITS} ) << $globals{ZONE_OFFSET};
    } else {
	$globals{ZONE_MASK} = 0;
    }

    if ( ( my $userbits = $config{PROVIDER_OFFSET} - $config{TC_BITS} ) > 0 ) {
	$globals{USER_MASK} = make_mask( $userbits ) << $config{TC_BITS};
	$globals{USER_BITS} = $userbits;
    } else {
	$globals{USER_MASK} = $globals{USER_BITS} = 0;
    }

    $val = $config{PROVIDER_OFFSET};

    $globals{SMALL_MAX} = $val ? make_mask( $val ) : $globals{TC_MASK}; 

    if ( supplied ( $val = $config{ZONE2ZONE} ) ) {
	fatal_error "Invalid ZONE2ZONE value ( $val )" unless $val =~ /^[2-]$/;
    } else {
	$config{ZONE2ZONE} = '-';
    }
```

## Disposition defaults block

```perl
    default 'BLACKLIST_DISPOSITION'    , 'DROP';

    unless ( ( $val = $config{BLACKLIST_DISPOSITION} ) =~ /^(?:A_)?DROP$/ || $config{BLACKLIST_DISPOSITION} =~ /^(?:A_)?REJECT/ ) {
	fatal_error q(BLACKLIST_DISPOSITION must be 'DROP', 'A_DROP', 'REJECT' or 'A_REJECT');
    }

    require_capability 'AUDIT_TARGET', "BLACKLIST_DISPOSITION=$val", 's' if $val =~ /^A_/;

    default 'SMURF_DISPOSITION'    , 'DROP';

    unless ( ( $val = $config{SMURF_DISPOSITION} ) =~ /^(?:A_)?DROP$/ ) {
	fatal_error q(SMURF_DISPOSITION must be 'DROP' or 'A_DROP');
    }

    require_capability 'AUDIT_TARGET', "SMURF_DISPOSITION=$val", 's' if $val =~ /^A_/;

    if ( supplied( $val = $config{LOG_LEVEL} ) ) {
	validate_level( $val );
    } else {
	$config{LOG_LEVEL} = 'info';
    }

    default_log_level 'BLACKLIST_LOG_LEVEL',  '';
    default_log_level 'MACLIST_LOG_LEVEL',    '';
    default_log_level 'TCP_FLAGS_LOG_LEVEL',  '';
    default_log_level 'RFC1918_LOG_LEVEL',    '';
    default_log_level 'RELATED_LOG_LEVEL',    '';
    default_log_level 'INVALID_LOG_LEVEL',    '';
    default_log_level 'UNTRACKED_LOG_LEVEL',  '';

    if ( supplied( $val = $config{LOG_BACKEND} ) ) {
	if ( $family == F_IPV4 && $val eq 'ULOG' ) {
	    $val = 'ipt_ULOG';
	} elsif ( $val eq 'netlink' ) {
	    $val = 'nfnetlink_log';
	} elsif ( $val eq 'LOG' ) {
	    $val = $family == F_IPV4 ? 'ipt_LOG' : 'ip6t_LOG';
	} else {
	    fatal_error "Invalid LOG Backend ($val)";
	}

	$config{LOG_BACKEND} = $val;
    }

    if ( supplied( $val = $config{LOG_ZONE} ) ) {
	fatal_error "Invalid LOG_ZONE setting ($val)" unless $val =~ /^(src|dst|both)$/i;
	$config{LOG_ZONE} = lc( $val );
    } else {
	$config{LOG_ZONE} = 'both';
    }

    warning_message "RFC1918_LOG_LEVEL=$config{RFC1918_LOG_LEVEL} ignored. The 'norfc1918' interface/host option is no longer supported" if $config{RFC1918_LOG_LEVEL};

    default_log_level 'SMURF_LOG_LEVEL',     '';
    default_log_level 'LOGALLNEW',           '';

    default_log_level 'SFILTER_LOG_LEVEL', 'info';

    if ( supplied( $val = $config{SFILTER_DISPOSITION} ) ) {
	fatal_error "Invalid SFILTER_DISPOSITION setting ($val)" unless $val =~ /^(A_)?(DROP|REJECT)$/;
	require_capability 'AUDIT_TARGET' , "SFILTER_DISPOSITION=$val", 's' if $1;
    } else {
	$config{SFILTER_DISPOSITION} = 'DROP';
    }

    default_log_level 'RPFILTER_LOG_LEVEL', 'info';

    if ( supplied ( $val = $config{RPFILTER_DISPOSITION} ) ) {
	fatal_error "Invalid RPFILTER_DISPOSITION setting ($val)" unless $val =~ /^(A_)?(DROP|REJECT)$/;
	require_capability 'AUDIT_TARGET' , "RPFILTER_DISPOSITION=$val", 's' if $1;
    } else {
	$config{RPFILTER_DISPOSITION} = 'DROP';
    }

    if ( supplied( $val = $config{MACLIST_DISPOSITION} ) ) {
	if ( $val =~ /^(?:A_)?DROP$/ ) {
	    $globals{MACLIST_TARGET} = $val;
	} elsif ( $val eq 'REJECT' ) {
	    $globals{MACLIST_TARGET} = 'reject';
	} elsif ( $val eq 'A_REJECT' ) {
	    $globals{MACLIST_TARGET} = $val;
	} elsif ( $val eq 'ACCEPT' ) {
	    $globals{MACLIST_TARGET} = 'RETURN';
	} else {
	    fatal_error "Invalid value ($config{MACLIST_DISPOSITION}) for MACLIST_DISPOSITION"
	}

	require_capability 'AUDIT_TARGET' , "MACLIST_DISPOSITION=$val", 's' if $val =~ /^A_/;
    } else {
	$config{MACLIST_DISPOSITION}  = 'REJECT';
	$globals{MACLIST_TARGET}      = 'reject';
    }

    if ( supplied( $val = $config{RELATED_DISPOSITION} ) ) {
	if ( $val =~ /^(?:A_)?(?:DROP|ACCEPT)$/ ) {
	    $globals{RELATED_TARGET} = $val;
	} elsif ( $val eq 'REJECT' ) {
	    $globals{RELATED_TARGET} = 'reject';
	} elsif ( $val eq 'A_REJECT' ) {
	    $globals{RELATED_TARGET} = $val;
	} elsif ( $val eq 'CONTINUE' ) {
	    $globals{RELATED_TARGET} = '';
	} else {
	    fatal_error "Invalid value ($config{RELATED_DISPOSITION}) for RELATED_DISPOSITION"
	}

	require_capability 'AUDIT_TARGET' , "RELATED_DISPOSITION=$val", 's' if $val =~ /^A_/;
    } else {
	$config{RELATED_DISPOSITION}  =
	$globals{RELATED_TARGET}      = 'ACCEPT';
    }

    if ( supplied( $val = $config{INVALID_DISPOSITION} ) ) {
	if ( $val =~ /^(?:A_)?DROP$/ ) {
	    $globals{INVALID_TARGET} = $val;
	} elsif ( $val eq 'REJECT' ) {
	    $globals{INVALID_TARGET} = 'reject';
	} elsif ( $val eq 'A_REJECT' ) {
	    $globals{INVALID_TARGET} = $val;
	} elsif ( $val eq 'CONTINUE' ) {
	    $globals{INVALID_TARGET} = '';
	} else {
	    fatal_error "Invalid value ($config{INVALID_DISPOSITION}) for INVALID_DISPOSITION"
	}

	require_capability 'AUDIT_TARGET' , "INVALID_DISPOSITION=$val", 's' if $val =~ /^A_/;
    } else {
	$config{INVALID_DISPOSITION}  = 'CONTINUE';
	$globals{INVALID_TARGET}      = '';
    }

    if ( supplied( $val = $config{UNTRACKED_DISPOSITION} ) ) {
	if ( $val =~ /^(?:A_)?(?:DROP|ACCEPT)$/ ) {
	    $globals{UNTRACKED_TARGET} = $val;
	} elsif ( $val eq 'REJECT' ) {
	    $globals{UNTRACKED_TARGET} = 'reject';
	} elsif ( $val eq 'A_REJECT' ) {
	    $globals{UNTRACKED_TARGET} = $val;
	} elsif ( $val eq 'CONTINUE' ) {
	    $globals{UNTRACKED_TARGET} = '';
	} else {
	    fatal_error "Invalid value ($config{UNTRACKED_DISPOSITION}) for UNTRACKED_DISPOSITION"
	}

	require_capability 'AUDIT_TARGET' , "UNTRACKED_DISPOSITION=$val", 's' if $val =~ /^A_/;
    } else {
	$config{UNTRACKED_DISPOSITION}  = 'CONTINUE';
	$globals{UNTRACKED_TARGET}        = '';
    }

    if ( supplied( $val = $config{MACLIST_TABLE} ) ) {
	if ( $val eq 'mangle' ) {
	    fatal_error 'MACLIST_DISPOSITION=$1 is not allowed with MACLIST_TABLE=mangle' if $config{MACLIST_DISPOSITION} =~ /^((?:A)?REJECT)$/;
	} else {
	    fatal_error "Invalid value ($val) for MACLIST_TABLE option" unless $val eq 'filter';
	}
    } else {
	default 'MACLIST_TABLE' , 'filter';
    }

    if ( supplied( $val = $config{TCP_FLAGS_DISPOSITION} ) ) {
	fatal_error "Invalid value ($config{TCP_FLAGS_DISPOSITION}) for TCP_FLAGS_DISPOSITION" unless $val =~ /^(?:(A_)?(?:REJECT|DROP))|ACCEPT$/;
	require_capability 'AUDIT_TARGET' , "TCP_FLAGS_DISPOSITION=$val", 's' if $1;
    } else {
	$val = $config{TCP_FLAGS_DISPOSITION} = 'DROP';
    }

    default 'TC_ENABLED' , $family == F_IPV4 ? 'Internal' : 'no';

    $val = "\L$config{TC_ENABLED}";

    if ( $val eq 'yes' ) {
	my $file = find_file 'tcstart';
	fatal_error "Unable to find tcstart file" unless -f $file;
	$globals{TC_SCRIPT} = $file;
    } elsif ( $val eq 'internal' ) {
	$config{TC_ENABLED} = 'Internal';
     } elsif ( $val eq 'shared' ) {
	$config{TC_ENABLED} = 'Shared';
    } elsif ( $val eq 'simple' ) {
	$config{TC_ENABLED} = 'Simple';
    } else {
	fatal_error "Invalid value ($config{TC_ENABLED}) for TC_ENABLED" unless $val eq 'no';
	$config{TC_ENABLED} = '';
    }

    if ( $config{TC_ENABLED} ) {
	fatal_error "TC_ENABLED=$config{TC_ENABLED} is not allowed with MANGLE_ENABLED=No" unless $config{MANGLE_ENABLED};
	require_mangle_capability 'MANGLE_ENABLED', "TC_ENABLED=$config{TC_ENABLED}", 's';
    }
```

## Logging defaults block

```perl
    default_log_level 'BLACKLIST_LOG_LEVEL',  '';
    default_log_level 'MACLIST_LOG_LEVEL',    '';
    default_log_level 'TCP_FLAGS_LOG_LEVEL',  '';
    default_log_level 'RFC1918_LOG_LEVEL',    '';
    default_log_level 'RELATED_LOG_LEVEL',    '';
    default_log_level 'INVALID_LOG_LEVEL',    '';
    default_log_level 'UNTRACKED_LOG_LEVEL',  '';

    if ( supplied( $val = $config{LOG_BACKEND} ) ) {
	if ( $family == F_IPV4 && $val eq 'ULOG' ) {
	    $val = 'ipt_ULOG';
	} elsif ( $val eq 'netlink' ) {
	    $val = 'nfnetlink_log';
	} elsif ( $val eq 'LOG' ) {
	    $val = $family == F_IPV4 ? 'ipt_LOG' : 'ip6t_LOG';
	} else {
	    fatal_error "Invalid LOG Backend ($val)";
	}

	$config{LOG_BACKEND} = $val;
    }

    if ( supplied( $val = $config{LOG_ZONE} ) ) {
	fatal_error "Invalid LOG_ZONE setting ($val)" unless $val =~ /^(src|dst|both)$/i;
	$config{LOG_ZONE} = lc( $val );
    } else {
	$config{LOG_ZONE} = 'both';
    }

    warning_message "RFC1918_LOG_LEVEL=$config{RFC1918_LOG_LEVEL} ignored. The 'norfc1918' interface/host option is no longer supported" if $config{RFC1918_LOG_LEVEL};
```

```perl
    if ( $val = $config{LOGFORMAT} ) {
	my $result;

	eval {
	    if ( $val =~ /%d/ ) {
		$globals{LOGRULENUMBERS} = 'Yes';
		$result = sprintf "$val", 'fooxx2barxx', 1, 'ACCEPT';
	    } else {
		$result = sprintf "$val", 'fooxx2barxx', 'ACCEPT';
	    }
	};

	fatal_error "Invalid LOGFORMAT ($val)" if $@;

	fatal_error "LOGFORMAT string is longer than 29 characters ($val)" if length $result > 29;

	$globals{MAXZONENAMELENGTH} = int ( 5 + ( ( 29 - (length $result ) ) / 2) );
    } else {
	$config{LOGFORMAT}='Shorewall:%s:%s:';
	$globals{MAXZONENAMELENGTH} = 5;
    }
```
