use strict;
use warnings;
use Test::More;
use IocHygiene qw(audit_text audit_path sort_findings rank refang);

sub rules { my ($t) = @_; return join ',', sort map { $_->{rule} } audit_text($t, 't.txt') }
sub first { return (audit_text($_[0], 't.txt'))[0] }

# refang
is(refang('hxxp://a[.]b'), 'http://a.b', 'hxxp and [.]');
is(refang('hxxps://a(.)b'), 'https://a.b', 'hxxps and (.)');
is(refang('a[dot]b'), 'a.b', '[dot]');
is(refang('a[@]b[.]c'), 'a@b.c', '[@]');
is(refang('http[:]//x'), 'http://x', '[:]');
is(refang('plain text'), 'plain text', 'plain text unchanged');
is(refang('hxxpfoo'), 'hxxpfoo', 'hxxp inside a word unchanged');

# IOC001
is(rules('see http://evil.example/a'), 'IOC001', 'live http URL');
is(rules('see https://evil.example/a?x=1&y=2'), 'IOC001', 'live https URL');
is(rules('see ftp://evil.example/a'), 'IOC001', 'live ftp URL');
is(rules('see HTTP://EVIL.EXAMPLE/a'), 'IOC001', 'uppercase URL');
is(rules('see hxxp://evil[.]example/a'), '', 'defanged URL clean');
is(rules('see hxxps://evil[.]example/a'), '', 'defanged https URL clean');
is(rules('see hxxp[:]//evil[.]example/a'), '', 'defanged colon');
is(rules('"http://evil.example/a",'), 'IOC001', 'URL in CSV quotes');
is(rules('(http://evil.example/a)'), 'IOC001', 'URL in parentheses');
is((first('http://evil.example/a'))->{sev}, 'high', 'IOC001 is high');
like((first('http://evil.example/a'))->{msg}, qr{hxxp://evil\[\.\]example/a}, 'message suggests defang');
is(rules('http://203.0.114.9/a'), 'IOC001', 'URL with IP counts once');

# IOC002 / IOC004 / IOC008
is(rules('c2 203.0.114.9'), 'IOC002', 'live public IP');
is(rules('c2 203[.]0[.]114[.]9'), '', 'defanged IP clean');
is(rules('c2 203(.)0(.)114(.)9'), '', 'defanged IP with parentheses');
is(rules('c2 203[dot]0[dot]114[dot]9'), '', 'defanged IP with [dot]');
is(rules('c2 203.0.114.9:443'), 'IOC002', 'IP with port');
is(rules('c2 203.0.114.9, 203[.]0[.]114[.]10'), 'IOC002', 'one live one defanged');
is(rules('v1.2.3.4'), 'IOC000', 'v prefix is a version');
is(rules('10.0.0.1'), 'IOC004', 'RFC1918 10/8');
is(rules('172.16.5.5'), 'IOC004', 'RFC1918 172.16/12');
is(rules('172.32.5.5'), 'IOC002', '172.32 is public');
is(rules('192.168.1.1'), 'IOC004', 'RFC1918 192.168/16');
is(rules('127.0.0.1'), 'IOC004', 'loopback');
is(rules('169.254.1.1'), 'IOC004', 'link-local');
is(rules('0.0.0.0'), 'IOC004', 'unspecified');
is(rules('192.0.2.10'), 'IOC004', 'documentation 192.0.2');
is(rules('198.51.100.10'), 'IOC004', 'documentation 198.51.100');
is(rules('203.0.113.10'), 'IOC004', 'documentation 203.0.113');
is(rules('100.64.0.1'), 'IOC004', 'CGNAT');
is(rules('224.0.0.1'), 'IOC004', 'multicast');
is(rules('300.1.1.1'), 'IOC008', 'invalid octet');
is(rules('1.2.3.256'), 'IOC008', 'octet 256');
is(rules('1.2.3'), 'IOC000', 'three octets is not an IP');
is(rules('1.2.3.4.5'), 'IOC000', 'five octets is not an IP');
is(rules('2026-11-16'), 'IOC000', 'date is not an IP');
is((first('203.0.114.9'))->{sev}, 'medium', 'IOC002 is medium');

# IOC003
is(rules('mail a@evil.example'), 'IOC003', 'live email');
is(rules('mail a[@]evil[.]example'), '', 'defanged email');
is(rules('mail a(@)evil.example'), '', 'defanged email (@)');
is((first('a@evil.example'))->{sev}, 'low', 'IOC003 is low');

# IOC005
my $md5 = 'd41d8cd98f00b204e9800998ecf8427f';
my $sha1 = '3f786850e387550fdab836ed7e6dc881de23001b';
my $sha256 = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
is(rules("md5: $md5"), '', 'md5 label matches');
is(rules("SHA1 $sha1"), '', 'sha1 label matches');
is(rules("sha-256: $sha256"), '', 'sha-256 label matches');
is(rules("sha256: $sha1"), 'IOC005', 'sha256 label with sha1 value');
is(rules("md5: $sha256"), 'IOC005', 'md5 label with sha256 value');
is(rules("sha1=" . substr($sha1, 0, 38)), 'IOC005', 'truncated sha1');
is(rules("sha512: $sha256"), 'IOC005', 'sha512 label with sha256 value');
is(rules($sha256), '', 'unlabelled hash clean');
is(rules(substr($sha256, 0, 50)), 'IOC000', 'odd length hex is not a hash');

# IOC006
is(rules("203[.]0[.]114[.]9\n203.0.114.9"), 'IOC002,IOC006', 'duplicate defanged then live');
is(rules("$sha256\n" . uc $sha256), 'IOC006', 'duplicate hash, case-insensitive');
is(rules("hxxp://a[.]example/x\nhxxp://a[.]example/x"), 'IOC006', 'duplicate defanged URL');
is(rules("a[@]b[.]example\na[@]b[.]example"), 'IOC006', 'duplicate email');
is(rules("1.1.1.1\n1.1.1.1"), 'IOC006,IOC007,IOC007', 'duplicate benign IP');
{
    my @f = audit_text("203[.]0[.]114[.]9\n203[.]0[.]114[.]9", 'x.txt');
    like($f[0]{msg}, qr/x\.txt:1/, 'duplicate points at first line');
    is($f[0]{line}, 2, 'duplicate reported on later line');
}
{
    my %seen;
    audit_text("203[.]0[.]114[.]9", 'a.txt', \%seen);
    my @f = audit_text("203[.]0[.]114[.]9", 'b.txt', \%seen);
    is($f[0]{rule}, 'IOC006', 'duplicate across files');
}
is(rules("203[.]0[.]114[.]9 and 203[.]0[.]114[.]9"), 'IOC006', 'same line twice');

# IOC007
is(rules('8.8.8.8'), 'IOC007', 'google dns');
is(rules('1.1.1.1'), 'IOC007', 'cloudflare dns');
is(rules('9.9.9.9'), 'IOC007', 'quad9');
is(rules('hxxps://github[.]com/x'), 'IOC007', 'benign domain');
is(rules('hxxps://api[.]github[.]com/x'), 'IOC007', 'benign subdomain');
is(rules('hxxps://notgithub[.]com/x'), '', 'lookalike domain is not benign');
is(rules('d41d8cd98f00b204e9800998ecf8427e'), 'IOC007', 'empty md5');
is(rules('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), 'IOC007', 'empty sha256');
is(rules('da39a3ee5e6b4b0d3255bfef95601890afd80709'), 'IOC007', 'empty sha1');
is((first('8.8.8.8'))->{sev}, 'medium', 'IOC007 is medium');

# references
is(rules("## References\nhttp://vendor.example/a\n"), 'IOC000', 'reference section skipped');
is(rules("## Sources\nhttp://vendor.example/a\n"), 'IOC000', 'sources section skipped');
is(rules("## References\nhttp://vendor.example/a\n## Indicators\nhttp://evil.example/b\n"), 'IOC001', 'next heading resumes');
is(rules("Reference: http://vendor.example/a\n"), 'IOC000', 'Reference: line skipped');
is(rules("source: http://vendor.example/a\n"), 'IOC000', 'source: line skipped');
is(rules("# Title\nhttp://evil.example/b\n"), 'IOC001', 'other heading is not skipped');

# IOC000 and input handling
is(rules(''), 'IOC000', 'empty');
is(rules("just words\nnothing here\n"), 'IOC000', 'no indicators');
is((first(''))->{sev}, 'info', 'IOC000 is info');
is(rules("http://evil.example/a\r\n203.0.114.9\r\n"), 'IOC001,IOC002', 'CRLF');
is(rules("\0\1\2\xff\xfe"), 'IOC000', 'binary text');
is(scalar(() = audit_text(undef, 'u.txt')), 1, 'undef text');

# line numbers and where
my @w = audit_text("a\n\n203.0.114.9\n", 'f.md');
is($w[0]{where}, 'f.md:3', 'where has file and line');
is($w[0]{line}, 3, 'line number');

# sorting
my @list = (
    { sev => 'low', file => 'a', line => 1, rule => 'B', msg => '' },
    { sev => 'high', file => 'z', line => 1, rule => 'A', msg => '' },
    { sev => 'high', file => 'a', line => 10, rule => 'A', msg => '' },
    { sev => 'high', file => 'a', line => 2, rule => 'A', msg => '' },
);
my @s = sort_findings(@list);
is(join(' ', map { "$_->{file}$_->{line}" } @s), 'a2 a10 z1 a1', 'sort by severity, file, numeric line');
ok(rank('critical') < rank('high') && rank('low') < rank('info'), 'rank order');

# audit_path on examples
my ($f, $n) = audit_path('examples');
is($n, 3, 'examples has three files');
ok((grep { $_->{rule} eq 'IOC001' } @$f), 'examples has IOC001');
my ($one, $n1) = audit_path('examples/reports/clean-list.txt');
is($n1, 1, 'single file');
is(scalar(@$one), 0, 'clean list has no findings');

# hostile input
ok(eval { audit_text('http://' . ('a' x 200000), 'big.txt'); 1 }, 'very long URL');
ok(eval { audit_text('1.' x 100000, 'big.txt'); 1 }, 'long dotted run');
ok(eval { audit_text(join("\n", ('203.0.114.9') x 20000), 'big.txt'); 1 }, 'many duplicate lines');
ok(eval { audit_text('a' x 500000, 'big.txt'); 1 }, 'long line without indicators');
ok(eval { audit_text("## References\n" x 1000, 'big.txt'); 1 }, 'many headings');

# fuzz
srand(7);
my @bits = ('http://', 'hxxp', '[.]', '(.)', '[@]', '@', '.', '1', '203', '256', 'md5', 'sha256', ':', ' ', "\n", 'a', 'b', 'example', 'com', '## References', '#', 'd41d8cd98f00b204e9800998ecf8427e', '8.8.8.8', '/', "\r");
my $bad = 0;
for my $i (1 .. 3000) {
    my $t = join '', map { $bits[ int rand @bits ] } 1 .. (1 + int rand 40);
    $bad++ unless eval { audit_text($t, 'f.txt'); 1 };
}
my $valid = "c2 203.0.114.9 http://evil.example/a sha256: $sha1 a\@evil.example\n";
for my $i (0 .. length $valid) {
    $bad++ unless eval { audit_text(substr($valid, 0, $i), 'f.txt'); 1 };
}
is($bad, 0, 'random and truncated inputs do not die');

done_testing();
