# filter-dkimverify

An OpenSMTPD filter that verifies DKIM signatures and checks SPF domain alignment on incoming messages. It inserts an `Authentication-Results` header with the verification outcome and can optionally reject messages that fail authentication.

## How it works

The filter integrates with OpenSMTPD's filter protocol to intercept incoming mail at the data phase:

1. Collects message lines as they arrive from OpenSMTPD
2. When the message is complete (signalled by `.`), performs DKIM signature verification using DNS lookups
3. Checks SPF alignment by comparing the DKIM signing domain against the envelope sender domain (relaxed alignment — organizational domain match is sufficient)
4. Inserts an `Authentication-Results` header at the top of the message body
5. If `--reject-on-fail` is enabled, rejects messages at the commit phase when DKIM verification fails or SPF alignment fails

## Building

Requires Rust 1.56+ (edition 2021).

```sh
cargo build --release
```

The binary will be at `target/release/filter-dkimverify`.

## Usage

```
filter-dkimverify [OPTIONS]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-H`, `--hostname <HOST>` | Hostname for the Authentication-Results header | `localhost` |
| `-r`, `--reject-on-fail` | Reject messages that fail DKIM/SPF checks | disabled |
| `--reject-message <MSG>` | Custom rejection message | `550 5.7.1 DKIM verification failed` |

### OpenSMTPD configuration

Add the filter to your `smtpd.conf`:

```
filter dkimverify proc-exec "/usr/local/libexec/filter-dkimverify -H mail.example.com"

listen on all filter dkimverify
```

To reject unauthenticated mail:

```
filter dkimverify proc-exec "/usr/local/libexec/filter-dkimverify -H mail.example.com --reject-on-fail"
```

### Logging

Logs are written to stderr at `info` level by default. Control verbosity with the `RUST_LOG` environment variable:

```
filter dkimverify proc-exec "RUST_LOG=debug /usr/local/libexec/filter-dkimverify -H mail.example.com"
```

## Example output

A passing message will have a header inserted like:

```
Authentication-Results: mail.example.com; dkim=pass (domain=example.com); spf=pass (domain alignment: example.com ~ example.com)
```

A failing message:

```
Authentication-Results: mail.example.com; dkim=fail (domain=spoofed.com, reason=signature verification failed); spf=fail (domain mismatch: attacker.com vs spoofed.com)
```

## License

ISC
