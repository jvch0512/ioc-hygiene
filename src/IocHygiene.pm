package IocHygiene;
use strict;
use warnings;
use File::Find ();
use Exporter 'import';
our @EXPORT_OK = qw(audit_text audit_path sort_findings rank refang);

my %RANK = (critical => 0, high => 1, medium => 2, low => 3, info => 4);
sub rank { return exists $RANK{ $_[0] } ? $RANK{ $_[0] } : 4 }

my $MAX_BYTES = 50_000_000;
my @EXT = qw(txt md csv tsv json ioc list);

my %BENIGN_IP = map { $_ => 1 } qw(8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112 208.67.222.222 208.67.220.220);
my %BENIGN_HASH = map { $_ => 1 } (
    'd41d8cd98f00b204e9800998ecf8427e',
    'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
);
my @BENIGN_DOMAIN = qw(google.com microsoft.com github.com apple.com amazon.com amazonaws.com cloudflare.com windowsupdate.com live.com office.com mozilla.org);

# Turns defanged indicators back into their live form.
sub refang {
    my ($s) = @_;
    $s =~ s/\bhxxp(s?)\b/http$1/gi;
    $s =~ s/\bfxp\b/ftp/gi;
    $s =~ s/\[:\]/:/g;
    $s =~ s/\[\.\]|\(\.\)|\[dot\]|\(dot\)/./gi;
    $s =~ s/\[@\]|\(@\)|\[at\]/@/gi;
    return $s;
}

sub _reserved {
    my ($a, $b, $c) = @_;
    return 1 if $a == 0 || $a == 10 || $a == 127 || $a >= 224;
    return 1 if $a == 169 && $b == 254;
    return 1 if $a == 172 && $b >= 16 && $b <= 31;
    return 1 if $a == 192 && $b == 168;
    return 1 if $a == 100 && $b >= 64 && $b <= 127;
    return 1 if $a == 192 && $b == 0 && $c == 2;
    return 1 if $a == 198 && $b == 51 && $c == 100;
    return 1 if $a == 203 && $b == 0 && $c == 113;
    return 0;
}

my $URL_RE = qr{\b(?:https?|ftp)://[^\s<>"'`\)\]\},;]+}i;
my $IP_RE  = qr/(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?!\d|\.\d)/;
my $MAIL_RE = qr/(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/;
my $HASH_RE = qr/(?<![0-9A-Fa-f])([0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{128})(?![0-9A-Fa-f])/;
my %LABEL_LEN = (md5 => 32, sha1 => 40, 'sha-1' => 40, sha256 => 64, 'sha-256' => 64, sha512 => 128, 'sha-512' => 128);

sub _host_of {
    my ($url) = @_;
    return $1 if $url =~ m{^[a-z]+://(?:[^/@]*@)?\[?([^/:\]?#]+)}i;
    return '';
}

sub audit_text {
    my ($text, $file, $seen) = @_;
    $seen ||= {};
    $text = '' unless defined $text;
    my @out;
    my $found = 0;
    my $skip = 0;
    my $n = 0;
    my $add = sub {
        my ($sev, $rule, $line, $msg) = @_;
        push @out, { sev => $sev, rule => $rule, file => $file, line => $line, where => "$file:$line", msg => $msg };
    };
    for my $raw (split /\r?\n/, $text, -1) {
        $n++;
        last if $n > 2_000_000;
        my $line = $raw;
        if ($line =~ /^\s{0,3}#{1,6}\s*(.*?)\s*#*\s*$/) {
            $skip = ($1 =~ /^(?:references?|sources?|further reading|links)\b/i) ? 1 : 0;
            next;
        }
        next if $skip;
        next if $line =~ /^\s*(?:reference|source|ref)s?\s*:/i;
        next if length($line) > 100_000;
        my $ref = refang($line);

        # URLs
        my %live_url;
        $live_url{ lc $_ }++ for ($line =~ /($URL_RE)/g);
        my @all_urls = ($ref =~ /($URL_RE)/g);
        for my $u (@all_urls) {
            $found = 1;
            my $key = 'url:' . lc $u;
            my $is_live = $live_url{ lc $u } ? 1 : 0;
            $live_url{ lc $u }-- if $is_live;
            $add->('high', 'IOC001', $n, "live URL $u should be defanged, for example " . _defang_url($u)) if $is_live;
            my $host = lc _host_of($u);
            for my $d (@BENIGN_DOMAIN) {
                if ($host eq $d || $host =~ /\.\Q$d\E$/) {
                    $add->('medium', 'IOC007', $n, "$host is a well-known benign domain, check this is really an indicator");
                    last;
                }
            }
            _dup($seen, $key, $file, $n, $add, $u);
        }

        # remove URLs before looking for bare IPs
        (my $l2 = $line) =~ s/$URL_RE/ /g;
        (my $r2 = $ref) =~ s/$URL_RE/ /g;

        # emails
        my %live_mail;
        $live_mail{ lc $_ }++ for ($l2 =~ /($MAIL_RE)/g);
        for my $m ($r2 =~ /($MAIL_RE)/g) {
            $found = 1;
            if ($live_mail{ lc $m }) {
                $live_mail{ lc $m }--;
                $add->('low', 'IOC003', $n, "live email address $m should be defanged, for example " . ($m =~ s/@/[@]/r));
            }
            _dup($seen, 'mail:' . lc $m, $file, $n, $add, $m);
        }

        # IPv4
        my %live_ip;
        $live_ip{$_}++ for ($l2 =~ /$IP_RE/g);
        for my $ip ($r2 =~ /$IP_RE/g) {
            $found = 1;
            my @o = split /\./, $ip;
            if (grep { $_ > 255 } @o) {
                $add->('low', 'IOC008', $n, "$ip is not a valid IPv4 address");
                next;
            }
            my $is_live = $live_ip{$ip} ? 1 : 0;
            $live_ip{$ip}-- if $is_live;
            my $norm = join '.', map { $_ + 0 } @o;
            if (_reserved(@o[0 .. 2])) {
                $add->('low', 'IOC004', $n, "$ip is a private or reserved address, unlikely to be an indicator");
            } elsif ($BENIGN_IP{$norm}) {
                $add->('medium', 'IOC007', $n, "$ip is a well-known public service, check this is really an indicator");
            } elsif ($is_live) {
                $add->('medium', 'IOC002', $n, "live IP address $ip should be defanged, for example " . ($ip =~ s/\./[.]/gr));
            }
            _dup($seen, "ip:$norm", $file, $n, $add, $ip);
        }

        # hashes
        for my $h ($line =~ /$HASH_RE/g) {
            $found = 1;
            my $lh = lc $h;
            $add->('medium', 'IOC007', $n, "$lh is the hash of an empty file, not an indicator") if $BENIGN_HASH{$lh};
            _dup($seen, "hash:$lh", $file, $n, $add, $lh);
        }
        while ($line =~ /\b(md5|sha-?1|sha-?256|sha-?512)\b\W{0,4}([0-9A-Fa-f]{16,})(?![0-9A-Fa-f])/gi) {
            my ($label, $val) = (lc $1, $2);
            $label =~ s/^sha(\d)/sha$1/;
            my $want = $LABEL_LEN{$label};
            next unless $want;
            $found = 1;
            if (length($val) != $want) {
                $add->('low', 'IOC005', $n, "labelled $label but the value has " . length($val) . " hex digits, expected $want");
            }
        }
    }
    if (!$found && !@out) {
        push @out, { sev => 'info', rule => 'IOC000', file => $file, line => 0, where => $file, msg => 'no indicators found' };
    }
    return @out;
}

sub _defang_url {
    my ($u) = @_;
    $u =~ s/^http/hxxp/i;
    $u =~ s{^([A-Za-z]+://)([^/:?#]+)}{ my ($p, $h) = ($1, $2); $h =~ s/\./[.]/g; "$p$h" }e;
    return $u;
}

sub _dup {
    my ($seen, $key, $file, $line, $add, $shown) = @_;
    if (my $first = $seen->{$key}) {
        $add->('low', 'IOC006', $line, "$shown is already listed at $first->[0]:$first->[1]");
    } else {
        $seen->{$key} = [$file, $line];
    }
}

sub sort_findings {
    return sort {
        rank($a->{sev}) <=> rank($b->{sev})
          or $a->{file} cmp $b->{file}
          or $a->{line} <=> $b->{line}
          or $a->{rule} cmp $b->{rule}
          or $a->{msg} cmp $b->{msg}
    } @_;
}

sub _files {
    my ($path) = @_;
    return ([ (split m{/}, $path)[-1], $path ]) unless -d $path;
    my %ext = map { $_ => 1 } @EXT;
    my @f;
    File::Find::find({
        no_chdir => 1,
        wanted => sub {
            return if -l $File::Find::name;
            if (-d $File::Find::name && $_ =~ m{(?:^|/)\.git$}) { $File::Find::prune = 1; return }
            return unless -f $File::Find::name;
            return unless $File::Find::name =~ /\.([A-Za-z0-9]+)$/ && $ext{ lc $1 };
            my $rel = $File::Find::name;
            $rel =~ s{^\Q$path\E/?}{};
            push @f, [ $rel, $File::Find::name ];
        },
    }, $path);
    return sort { $a->[0] cmp $b->[0] } @f;
}

sub audit_path {
    my ($path) = @_;
    my @files = _files($path);
    my %seen;
    my @all;
    for my $f (@files) {
        my $text = '';
        if (-s $f->[1] && -s $f->[1] <= $MAX_BYTES && open(my $fh, '<:raw', $f->[1])) {
            local $/;
            $text = <$fh>;
            close $fh;
        }
        push @all, audit_text($text, $f->[0], \%seen);
    }
    return ([ sort_findings(@all) ], scalar @files);
}

1;
