# Chains.pm — extracted functions

**Source**: `Shorewall/Perl/Shorewall/Chains.pm`
**Git tag**: 5.2.6.1
**Purpose**: Reference for shorewall-nft Phase 6 work-package agents.

## Index

- `log_rule_limit` (lines 6844–6941): log-fragment builder (iptables string version)
- `log_irule_limit` (lines 6943–7036): log-fragment builder (irule/ijump version)
- `log_rule` (lines 7041–7045): wrapper using global LOGLIMIT
- `log_irule` (lines 7047–7051): wrapper using global LOGILIMIT
- `get_action_disposition` (Config.pm lines 3880–3886): current action disposition getter
- `set_action_disposition` (Config.pm lines 3887–3891): current action disposition setter

## log_rule_limit (lines 6844–6941)

> log-fragment builder (iptables string version)

```perl
sub log_rule_limit( $$$$$$$$;$ ) {
    my ($level, $chainref, $chn, $dispo, $limit, $tag, $command, $matches, $origin ) = @_;

    my $prefix = '';
    my $chain            = get_action_chain_name  ||  $chn;
    my $disposition      = get_action_disposition || $dispo;
    my $original_matches = $matches;
    my $ruleref;

    $level = validate_level $level; # Do this here again because this function can be called directly from user exits.

    return $dummyrule if $level eq '';

    $matches .= ' ' if $matches && substr( $matches, -1, 1 ) ne ' ';

    unless ( $matches =~ /-m (?:limit|hashlimit) / ) {
	$limit = $globals{LOGLIMIT} unless $limit && $limit ne '-';
	$matches .= $limit if $limit;
    }

    if ( $config{LOGFORMAT} =~ /^\s*$/ ) {
	if ( $level =~ '^ULOG' ) {
	    $prefix = "-j $level ";
	} elsif  ( $level =~ /^NFLOG/ ) {
	    $prefix = "-j $level ";
	} else {
	    my $flags = $globals{LOGPARMS};

	    if ( $level =~ /^(.+)\((.*)\)$/ ) {
		$level = $1;
		$flags = join( ' ', $flags, $2 ) . ' ';
		$flags =~ s/,/ /g;
	    }

	    $prefix = "-j LOG ${flags}--log-level $level ";
	}
    } else {
	if ( $tag ) {
	    if ( $config{LOGTAGONLY} && $tag ne ',' ) {
		if ( $tag =~ /^,/ ) {
		    ( $disposition = $tag ) =~ s/,//;
		} elsif ( $tag =~ /,/ ) {
		    ( $chain, $disposition ) = split ',', $tag, 2;
		} else { 
		    $chain = $tag;
		}

		$tag   = '';
	    } else {
		$tag .= ' ';
	    }
	} else {
	    $tag = '' unless defined $tag;
	}

	$disposition =~ s/\s+.*//;

	if ( $globals{LOGRULENUMBERS} ) {
	    $prefix = (sprintf $config{LOGFORMAT} , $chain , $chainref->{log}++, $disposition ) . $tag;
	} else {
	    $prefix = (sprintf $config{LOGFORMAT} , $chain , $disposition) . $tag;
	}

	if ( length $prefix > 29 ) {
	    $prefix = substr( $prefix, 0, 28 ) . ' ';
	    warning_message "Log Prefix shortened to \"$prefix\"";
	}

	if ( $level =~ '^ULOG' ) {
	    $prefix = "-j $level --ulog-prefix \"$prefix\" ";
	} elsif  ( $level =~ /^NFLOG/ ) {
	    $prefix = "-j $level --nflog-prefix \"$prefix\" ";
	} elsif ( $level =~ '^LOGMARK' ) {
	    $prefix = join( '', substr( $prefix, 0, 12 ) , ':' ) if length $prefix > 13;
	    $prefix = "-j $level --log-prefix \"$prefix\" ";
	} else {
	    my $options = $globals{LOGPARMS};

	    if ( $level =~ /^(.+)\((.*)\)$/ ) {
		$level   = $1;
		$options = join( ' ', $options, $2 ) . ' ';
		$options =~ s/,/ /g;
	    }

	    $prefix = "-j LOG ${options}--log-level $level --log-prefix \"$prefix\" ";
	}
    }

    if ( $command eq 'add' ) {
	$ruleref = add_rule ( $chainref, $matches . $prefix , $original_matches );
    } else {
	$ruleref = insert_rule1 ( $chainref , 0 , $matches . $prefix );
    }

    $ruleref->{origin} = $origin if reftype( $ruleref ) && $origin;

    $ruleref;
}
```

## log_irule_limit (lines 6943–7036)

> log-fragment builder (irule/ijump version)

```perl
sub log_irule_limit( $$$$$$$$@ ) {
    my ($level, $chainref, $chn, $dispo, $limit, $tag, $command, $origin, @matches ) = @_;

    my $prefix = '';
    my %matches;
    my $chain       = get_action_chain_name  ||  $chn;
    my $disposition = get_action_disposition || $dispo;
    my $original_matches = @matches;

    $level = validate_level $level; # Do this here again because this function can be called directly from user exits.

    return 1 if $level eq '';

    %matches = @matches;

    unless ( $matches{limit} || $matches{hashlimit} ) {
	$limit = $globals{LOGILIMIT} unless @$limit;
	push @matches, @$limit if @$limit;
    }

    if ( $config{LOGFORMAT} =~ /^\s*$/ ) {
	if ( $level =~ '^ULOG' ) {
	    $prefix = "$level";
	} elsif  ( $level =~ /^NFLOG/ ) {
	    $prefix = "$level";
	} else {
	    my $flags = $globals{LOGPARMS};

	    if ( $level =~ /^(.+)\((.*)\)$/ ) {
		$level = $1;
		$flags = join( ' ', $flags, $2 ) . ' ';
		$flags =~ s/,/ /g;
	    }

	    $prefix = "LOG ${flags}--log-level $level";
	}
    } else {
	if ( $tag ) {
	    if ( $config{LOGTAGONLY} && $tag ne ',' ) {
		if ( $tag =~ /^,/ ) {
		    ( $disposition = $tag ) =~ s/,//;
		} elsif ( $tag =~ /,/ ) {
		    ( $chain, $disposition ) = split ',', $tag, 2;
		} else { 
		    $chain = $tag;
		}

		$tag   = '';
	    } else {
		$tag .= ' ';
	    }
	} else {
	    $tag = '' unless defined $tag;
	}

	$disposition =~ s/\s+.*//;

	if ( $globals{LOGRULENUMBERS} ) {
	    $prefix = (sprintf $config{LOGFORMAT} , $chain , $chainref->{log}++, $disposition ) . $tag;
	} else {
	    $prefix = (sprintf $config{LOGFORMAT} , $chain , $disposition) . $tag;
	}

	if ( length $prefix > 29 ) {
	    $prefix = substr( $prefix, 0, 28 ) . ' ';
	    warning_message "Log Prefix shortened to \"$prefix\"";
	}

	if ( $level =~ '^ULOG' ) {
	    $prefix = "$level --ulog-prefix \"$prefix\"";
	} elsif  ( $level =~ /^NFLOG/ ) {
	    $prefix = "$level --nflog-prefix \"$prefix\"";
	} elsif ( $level =~ '^LOGMARK' ) {
	    $prefix = join( '', substr( $prefix, 0, 12 ) , ':' ) if length $prefix > 13;
	    $prefix = "$level --log-prefix \"$prefix\"";
	} else {
	    my $options = $globals{LOGPARMS};

	    if ( $level =~ /^(.+)\((.*)\)$/ ) {
		$level   = $1;
		$options = join( ' ', $options, $2 ) . ' ';
		$options =~ s/,/ /g;
	    }

	    $prefix = "LOG ${options}--log-level $level --log-prefix \"$prefix\"";
	}
    }

    if ( $command eq 'add' ) {
	add_ijump_internal ( $chainref, j => $prefix , $original_matches, $origin, @matches );
    } else {
	insert_ijump ( $chainref, j => $prefix, 0 , @matches );
    }
}
```

## log_rule (lines 7041–7045)

> wrapper using global LOGLIMIT

```perl
#
# Wrappers for the above that use the global default log limit
#
sub log_rule( $$$$ ) {
    my ( $level, $chainref, $disposition, $matches ) = @_;

    log_rule_limit $level, $chainref, $chainref->{logname} , $disposition, $globals{LOGLIMIT}, '', 'add', $matches;
}
```

## log_irule (lines 7047–7051)

> wrapper using global LOGILIMIT

```perl
sub log_irule( $$$;@ ) {
    my ( $level, $chainref, $disposition, @matches ) = @_;

    log_irule_limit $level, $chainref, $chainref->{logname} , $disposition, $globals{LOGILIMIT} , '', 'add', '', @matches;
}
```

## get_action_disposition (Config.pm lines 3880–3886)

> current action disposition getter

```perl
sub get_action_disposition() {
    $actparams{disposition};
}
```

## set_action_disposition (Config.pm lines 3887–3891)

> current action disposition setter

```perl
#
# Set the current action disposition for subsequent logging
#
sub set_action_disposition($) {
    $actparams{disposition} = $_[0];
}
```
