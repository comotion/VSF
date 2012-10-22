#!/usr/bin/perl
#
# 2009-08-04 Kacper Wysocki <kwy@redpill-linpro.com>
#
# Usage: 2vcl.pl foo.conf > bar.vcl
# 
# Unsupported variables:
#   REQUEST_LINE
# X-VSF-VCL-mod
use strict;

# kill newlines and leading spaces
our $TABLEVEL = 0;
our $TABSIZE = 3;
our $TABCHAR = ' ';
our $DEFAULT_ACTION = q(call sec_default_handler;);
our $DENY_ACTION = q(call sec_default_handler;);

our $DEBUG = 0;

# don't touch these, eh?

# ".*?\\".*?[^\\]"
# 

my $re_vararg = '[\w_-\d\:\/\*&!\|\'()^$]+';
#my $re_op = q("[^\\"]*(\\.[^\\"]*)*"|[^\s"']+|'[^\\']*(\\.[^\\']*)*');#|"[^"]*"|'[^']*');
my $re_op = qq(".*?[^\\\\]"|[^\s"']|'.*?[^\\\\]');
my $re_var = '[\w_\d]+';
#my $re_arg = ':[\w\d\*\/\|\'\-()\^\$]+';
my $re_arg = q(:'.+[^\\\\]'|:[_\w\d\*\/\(\)&\^\$-]+|:'/[\w\d\*\/\(\)|\^\$-]/');
my $re_num = q('?(\d*)'?);

sub skip_rule {
   my ($var, $func, $arg) = @_;
   # this is an expression that returns true or false
   $var =~ /^(XML|                 # XML body parse
              WEBSERVER_ERROR_LOG| # errorlog something
              REQUEST_BODY|        # raw body
              REQUEST_LINE|        # whole HTTP request
              REQBODY_PROCESSOR|   # body parse error
              REMOTE_HOST|         # we don't resolve
              REMOTE_ADDR|         # we don't resolve
              RESPONSE_            # any response logic
             )/x or $func =~ 
      /validate(UrlEncoding|ByteRange|Utf8Encoding)|lt|le|gt|ge|eq|ne|pm/x or
      ($var eq 'REQUEST_HEADERS' and not $arg)
}
sub emit {
   my $out = join " ", @_;
   print $TABCHAR x ($TABLEVEL * $TABSIZE) . qq($out\n);
}
# indent more
sub memit {
   $TABLEVEL++;
   emit @_;
}
# indent less
sub lemit {
   $TABLEVEL--;
   emit @_;
}
# indent after
sub aemit {
   emit @_;
   $TABLEVEL++;
}

sub killnil {
   s/^\s*(.*)\n?$/\1/;
}

# skip empty lines and comments
sub skip_line {
   while($_ and /^\s*#?\s*$/){
      $_ = <>;
      chomp;
   }
}

sub normalize_line {
   killnil;
   # normalize line: join escaped multilines
   while(/\\$/){
         chop;
         $_ .= <>;
         killnil;
   }
}

sub parse_input {
   aemit q(sub vcl_recv {);
   emit     q(set req.http.X-VSF-Module = "2vcl";);

   while(<>){
      parse_line();
      # I monk around with <>, so we gots to recheck eof
      last if eof;
   }
   lemit qq(}\n);
}

sub parse_line {
   skip_line;
   normalize_line;
   # Syntax: SecRule VARIABLES OPERATOR [ACTIONS]
   if(/^SecRule\s*("?$re_vararg"?)\s*($re_op)\s*(.*)?$/){
      my ($vars, $ops, $actions) = ($1, $2, $3);
      print STDERR "# line: VAR: $vars\n#OP: $ops\n#ACT: $actions\n" if $DEBUG == 2;
      #emit "# line: VAR: $vars\n#OP: $ops\n#ACT: $actions\n";
      parse_secrule($vars,$ops,$actions);
   }elsif(/^SecRule\s*($re_vararg)\s*/){
      print STDERR "#2 Rule fell thru cracks: $_\n";
   }elsif(/^SecRule/){
      print STDERR "#3 Rule fell thru cracks: $_\n";
   }
   # Other rule modifiers / matcher
}

sub emit_rule {
   my ($target, $ops, $neg_op, $neg_var, $func, $action) = @_;
   
   # pm pmFromFile rbl
   # validateUrlEncoding/Utf8Encoding verifyCC
   # within => acl
   $func = parse_func($func);
   if($func eq 'beginsWith'){
      $func = '~';
      $ops = '^'.$ops;
   }elsif($func eq 'endsWith'){
      $func = '~';
      $ops .= '$';
   }elsif($func eq 'pm'){
      # uses funky Aho-Corasick fast collection matching
      # we could use ACLs here to match on collection
      $func = '~';
      #$ops = emit_acl(split / /,$ops);
      
      $ops = '('. join "|",split / /,$ops .')';
   }elsif($func eq 'within'){
      $func = '~';
      my $tmp = '('. join "|",split / /,$ops .')';
      $ops = $target;
      $target = $tmp;
   }

   aemit qq(if($neg_op$target $func "$ops"){);
   emit_action($action,$target,$ops,$neg_op,$neg_var,$func);
   lemit qq(});
}

# translate funcs
sub parse_func {
   my ($func) = @_;
   if(not $func or $func eq 'rx') {
      $func = '~';
   }elsif($func eq 'eq'){
      $func = '==';
   }elsif($func eq 'ge'){
      $func = '>=';
   }elsif($func eq 'le'){
      $func = '<=';
   }elsif($func eq 'gt'){
      $func = '>';
   }elsif($func eq 'lt'){
      $func = '<';
   }elsif($func eq 'contains'){
      $func = '~';
   }
   return $func;
}
sub parse_secrule {
   my ($vars, $ops, $actions) = @_;

   # parse OPERATOR (regex default)
   my $neg_op;
   my $func;
   print STDERR "parse_ops($ops)\n" if $DEBUG == 3;
   ($func, $ops) = parse_ops($ops);
   # parse VARIABLES

   print STDERR "split_vars(;;$vars;;)\n" if $DEBUG >= 2;

   my @var = split_vars($vars);

   print STDERR "each vars..\n" if $DEBUG == 3;
   #my @var = split /\|/, $vars;
   for (@var){
      my ($var, $arg, $neg_var, $amp) = split_args($_);
      emit "#1 $vars: Var slipped thu: '$_'\n" if not $var;

      # skip this rule if it is not interesting
      # ie if we can't match for it in VCL yet
      if(skip_rule($var,$func,$arg) ){
         print STDERR "skipped $var $func :$arg\n" if $DEBUG == 2;
         emit qq(# skipped $neg_var $amp $var $func $arg $ops);
         next;
      }
      emit qq(## Rule: $var $func :$arg);

      emit_code($var,$ops,$actions,$func,$arg,$neg_var,$neg_op,$amp);
   }
}
sub split_vars {
   my ($vars, @var) = @_;
   $vars =~ s/^"(.*)"$/$1/;
   print STDERR "splitting $vars \n" if $DEBUG >= 2;
   my $prev = '';
   while($vars){
      $vars =~ s/^(&?TX|GLOBAL):'?\/([^\/]+)\/?'?// and # Such an ugly hack, doesn't account for TX:'/VAR nor anythin
         push @var, "$1:re($2)" and next;
      $vars =~ s/([\!\&]?(?:$re_var)(?:$re_arg)?)\|?//; # welcome to ehll
      push @var, $1;
      #print STDERR "PUSH $1\n";
      #print STDERR "#REDUCE: $vars\n";
      die "loop detected" if $vars and $prev eq $vars;
      $prev = $vars;

   }
   return @var;
}

sub split_args {
   ($_) = @_;
   my ($neg_var, $amp, $var, $arg) = /(!?)(&?)($re_var)($re_arg)?/;
   # get rid of :'/(
   emit qq(## $neg_var$amp$var, $arg);
   if($arg =~ /:'\/^?\(([^']*)\)\$?\/'/){
      $arg = $1;
      emit q(# AA );
   }elsif($arg =~ /:"\/^?\(([^"]*)\)\$?\/"/){
      $arg = $1;
      emit q(# AB );
   }elsif($arg =~ /:([^'"]+)/){
      $arg = $1;
      emit qq(# AC $arg );
   }
   return ($var, $arg, $neg_var, $amp);
}

sub parse_ops {
   my ($ops) = @_;
   my $neg;
   my $func = 'rx'; # regex is the default operator
   if($ops =~ /^"?(!?)(@?)(.*?[^\\])"?$/){
      $neg = $1;
      if($2 eq '@'){
         ($func, $ops) = split / /,$3,2;
      }else{
         $ops = $3;
      }
      # translate pcre to posix regex
      # no longer! v3 has pcre
      #$ops =~ s/\\?%/%25/g;
      #$ops =~ s/\\"/%22/g;
      #$ops =~ s/\(\?:/\(/g;
      #$ops =~ s/([^\\])([\{\}])/$1\\$2/g;
      #print "OP: $neg_op\@$func $ops\n";
   }else{
      print STDERR "error '$ops'\n$_\n";
   }
   return ($func, $ops, $neg);
}

# Do the dirty deed: map ModSec to vcl
sub emit_code {
   my ($var,$ops,$action,$func,$arg,$neg_var,$neg_op,$amp) = @_;
   my $target;
   my $status = '800';
   my $msg = 'Hack attack, try again.';
   print STDERR "# code VAR: $var\n#OP: $ops\n#ACT: $action\n" if $DEBUG;
   
   #emit qq(## $neg_var $amp $var \@$func $arg $ops); # : $actions
   if($var eq 'REQUEST_HEADERS' and $arg){
   # Support REQUEST_HEADERS:foo
      $arg =~ s#^:'/\^\((.*?)\)\$/'#$1#;
      emit qq(# AAA $arg);
      my @args = split /\|/,$arg;
      for(@args){
         $target = "req.http.$_";
         emit_rule($target,$ops,$neg_op,$neg_var,$func,$action);
      }
   }elsif($var =~/^ARGS/){ # ARGS, ARGS_NAMES, ARGS_GET etc..
      # XXX ARGS should only apply to param _values_ ?p=v&q=w
      $target = 'req.url';
      emit_rule($target,$ops,$neg_op,$neg_var,$func,$action);
   }else{
      if($var =~ /^(REQUEST_URI_RAW|REQUEST_URI)$/){
         $target = 'req.url';
      }elsif($var eq 'REQUEST_METHOD'){
         $target = "req.request";
      }elsif($var eq 'REQUEST_PROTOCOL'){
         $target = "req.proto";
      }elsif($var eq 'REMOTE_ADDR'){
         $target = 'client.ip';
         # More hacks!
         $ops =~ s/\\|\^|\$//g;
      }elsif($var =~ /^REQUEST_COOKIES/){
         $target = 'req.http.Cookie';
      }elsif($var eq 'REQUEST_FILENAME'){
         # XXX should be URL minus QUERY
         $target = 'req.url';
      }

      if($target){
         emit_rule($target,$ops,$neg_op,$neg_var,$func,$action);
      }
   }

}
# default action: phase:2,log,auditlog,pass
# deal with chains!
sub emit_action {
   my ($action,$target,$ops,$neg_op,$neg_var,$func) = @_;
   $action =~ s/^"([^"]*)"$/$1/;
   #emit "## ACTION $action\n";
   my @act = split /,/, $action;
   my ($chain, $phase);
   my $transforms = ''; #no default xforms
   my $end = $DEFAULT_ACTION;
   my $id;
   for(@act){
      # APEShiT: The Action Parse Engine Short Circuit
      # Warning! An expression must return TRUE
      # to stop matching the next 'or' clause.
      # In particular, assigments return the assigned value
      # which is FALSE if it is an empty string
      /phase:(\d*)/ and $phase = $1 or
      /chain/ and $chain = 1 or
      /status:$re_num/ and 
         emit qq(set req.http.X-VSF-Return = "$1";) or
      /severity:'?(\d*)'/ and 
         emit qq(set req.http.X-VSF-Severity = "$1";) or
      /id:$re_num/ and
         $id = $1 or
      /rev:$re_num/ and
         $id .= "-$1" or
      /tag:'([^']*)'/ and 
         emit qq(set req.http.X-VSF-RuleName = "$1";) or
      /msg:'([^']*)'/ and
         emit qq(set req.http.X-VSF-RuleInfo = "$1";) or
      /t:none/ and
         $transforms = '' or 1 or
      /t:(.*)/ and
         $transforms .= "$1;" or
      /allow:phase/ and
         emit qq(# should last in this phase..) and 
         emit qq(deliver;) or
      /allow:request/ and
         emit qq(# skip to RESPONSE_HEADERS..) and
         emit qq(deliver;) or
      /allow/ and emit qq(deliver;) or

      /(audit)?log(.*)/ and emit qq(# $1log$2 this plz) or
      /block/ and 
         $end = $DEFAULT_ACTION or
      /deny/ and 
         $end = $DENY_ACTION or
      /drop/ and 
         emit qq(# send a FIN and drop) and
         $end = $DENY_ACTION or
      /pass/ and
         emit qq(# pass to next rule) and $end = '' or
      /skip:$re_num/ and
         emit qq(# rule action skips next $1 rules!) or
      /skipAfter:$re_num/ and
         emit qq(# rule action skips after id/marker $1) or
      /pause:(.*)/ and
         emit qq(# sleep $1) or
      /proxy:(.*)/ and
         emit qq(# proxy to host: $1) or
      /redirect:(.*)/ and
         emit qq(# redirect to $1) or 
      /exec:(.*)/ and emit qq(# exec $1) or
      /capture/ and emit qq(# capture action) or
      /ctl:(.*)/ and emit qq(# ctl:$1) or
      /(pre|ap)pend:(.*)/ and emit qq(# body $1pend $2) or
      emit qq(# action : $_)
   }
   if($id){
      emit qq(set req.http.X-VSF-RuleId = "$id";);
   }
   emit qq(# transforms: $transforms) if $transforms;
   if($chain){
      emit qq(# chained rule);
      $end = '';
      $_ = ''; parse_line;
   }
   emit $end if $end;
}

parse_input;
