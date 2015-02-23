#!/usr/bin/perl
 
################################################################################
#
# nessus2csv.pl
#
# parse nessus files and outputs a csv file to STDOUT
# with a summary of findings per machine
#
#
# v1.0 05/12/2013 - Josep Fontana - Initial version
#
# TODO: 
# 


################################################################################
# init and argument parsing
################################################################################

# if a CPAN module is not installed, run
# $ perl -MCPAN -e 'install MODULE'
use warnings;
#use Nmap::Parser;
#use NetAddr::IP;
use Getopt::Std;
$Getopt::Std::STANDARD_HELP_VERSION = 1;
#use XML::SAX;

my $green = "\e[32m"; # originally "\e[32;40m"
my $bold = "\e[1m";
my $normal = "\e[0m";

my %options;
getopts( 'o:', \%options ) or HELP_MESSAGE();
my @files = @ARGV;
print "XXXX\n" if ( @files ~~ () );
#####
# we could also get just @ARGV[]
#####


################################################################################
# parsing nessus files to prepare variables
################################################################################

# global variables that are filled while parsing files
my @hosts; 			# list of hosts
my @plugins; 		# list of all plugin id present in nessus files
my %plugin_desc; 	# the key is the plugin id, the value is a string with the description
my %plugin_score; 	# the key is the plugin id, the value is a string with the criticality
my %findings; 		# nested hash with the host and the plugin as 1st and 2nd keys
my @context; 		# current (tag, host, plugin)

use XML::Parser;
my $parser = XML::Parser->new( Handlers => {
	Init => \&handle_doc_start,
	Final => \&handle_doc_end,
	Start => \&handle_elem_start,
	End => \&handle_elem_end,
	Char => \&handle_char_data,
});

# release the parser!
foreach $file (@files) {
	$parser->parsefile( $file );
}


################################################################################
# 
################################################################################

# use Data::Dumper;
# print "\n *** %findings ***\n\n";
# print Dumper %findings;
# print "\n *** \@hosts ***\n\n";
# print Dumper @hosts;
# print "\n *** \@plugins ***\n\n";
# print Dumper @plugins;
# print "\n *** %plugin_desc ***\n\n";
# print Dumper %plugin_desc;
# print "\n *** %plugin_score ***\n\n";
# print Dumper %plugin_score;


################################################################################
# write output based on:
#   @hosts: list of hosts
#   @plugins: list of all plugin id present in nessus files
#	%plugin_desc: the key is the plugin id, the value is a string with the description
#	%plugin_score: the key is the plugin id, the value is a string with the criticality
#   %findings: nested hash with the host and the plugin as 1st and 2nd keys and  
################################################################################



{
	# print the CSV file headers
	$, = ',';
	print "Risk,Plugin ID,Description",@hosts,"\n";
}


 # print each plugin line, ordered by risk factor
foreach $risk ('Critical', 'High', 'Medium', 'Low', 'None'){
	foreach $plugin (@plugins) {
		if ($risk ~~ $plugin_score{$plugin}) {
			print "$plugin_score{$plugin},$plugin,$plugin_desc{$plugin}";
			foreach $host (@hosts) {
				if ( $findings{$host}{$plugin} ) {
					print ',X';
				} else {
					print ',';
				}
			}
			print "\n";
		}
	}
}

exit;


################################################################################
# HANDLERS for the XML parser
################################################################################


# foreach $file (@files)
#	if !($file is well formed)
#		print " *** $file is not well formed: $!\n";
#		next;
#
#	start parsing $file
#
#	foreach ReportHost
#		$hostname = NessusClientData_v2/Report/ReportHost(name);
#		add $hostname to @hosts;
#
#		foreach ReportItem
#			$plugin = NessusClientData_v2/Report/ReportItem(pluginID);
#			%findings{$hostname}{$plugin} = 'X';
#			if !(@plugins contains $plugin)
#				add $plugin to @plugins;
#				$plugin_desc = NessusClientData_v2/Report/ReportItem(pluginName);
#				%plugin_desc{$plugin} = $plugin_desc;
#				$plugin_score = NessusClientData_v2/Report/ReportItem/risk_factor[value];
#				%plugin_score{$plugin} = $plugin_score;


sub handle_doc_start {
#	print "Start to parse document\n";
}


sub handle_elem_start {
	my( $expat, $name, %atts ) = @_;
	$context[0] = $name;
	
	if ( $context[0] eq 'ReportHost' ) {
		$context[1] = $atts{name};
		push ( @hosts, $atts{name} );
	} elsif ( $context[0] eq 'ReportItem' ) {
		$context[2] = $atts{pluginID};
		$findings{$context[1]}{$context[2]} = 'X';
		
		if (!($atts{pluginID} ~~ @plugins)) {
			push ( @plugins, $atts{pluginID} );
			$plugin_desc{$atts{pluginID}} = $atts{pluginName};
		}
	}
}


sub handle_elem_end {
	$context[0] = '';
}


sub handle_char_data {
	my( $expat, $score ) = @_;
#	print "    Plugin $context[2] has risk factor $score, wow!\n" if ( $context[0] eq 'risk_factor' );
	$plugin_score{$context[2]} = $score if ( $context[0] eq 'risk_factor' );
}


sub handle_doc_end {
	#print "Finished!\n";
}


################################################################################
# progress bar
# taken from http://oreilly.com/pub/h/943# HANDLERS
################################################################################

sub progress_bar {
    my ( $got, $total, $width, $char, $object ) = @_;
    $width ||= 25; $char ||= '=';
    my $num_width = length $total;
    sprintf "|%-${width}s| Done %${num_width}s $object of %s ($green%.2f%%$normal)\r", 
        $char x (($width-1)*$got/$total). '>', 
        $got, $total, 100*$got/+$total;
}


################################################################################
# Help & Version
################################################################################

sub VERSION_MESSAGE {
	print "\nnessus2csv.pl v1.0\n";
	exit();
}

sub HELP_MESSAGE {
	print "
parse nessus files and outputs a csv file to STDOUT with a summary of findings per machine

Usage: perl nessus2csv.pl --help --version file1.nessus file2.nessus ...

	--help			this help message

	--version		show version\n";
	exit();
}
