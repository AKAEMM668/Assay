# Fixture provenance

Captured 2026-08-10 from live public sources, except `velo-no-home-domain`
which was captured 2026-09-28 (that directory's `captured.date` records the
date, and `loadSubject` reads it so evidence retrieval times agree with this
file).
Each directory is one labelled subject for the eval in docs/eval.md.

| file | source URL |
| --- | --- |
| `aqua-clear-verified/asset.json` | https://horizon.stellar.org/assets?asset_code=AQUA&asset_issuer=GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA |
| `aqua-clear-verified/account.json` | https://horizon.stellar.org/accounts/GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA |
| `aqua-clear-verified/stellar.toml` | https://aqua.network/.well-known/stellar.toml |
| `aqua-clear-verified/blocked.json` | https://api.stellar.expert/explorer/directory/blocked-domains/aqua.network |
| `aqua-clear-verified/directory.json` | https://api.stellar.expert/explorer/directory/GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA |
| `shx-clear-flagslocked/asset.json` | https://horizon.stellar.org/assets?asset_code=SHX&asset_issuer=GDSTRSHXHGJ7ZIVRBXEYE5Q74XUVCUSEKEBR7UCHEUUEK72N7I7KJ6JH |
| `shx-clear-flagslocked/account.json` | https://horizon.stellar.org/accounts/GDSTRSHXHGJ7ZIVRBXEYE5Q74XUVCUSEKEBR7UCHEUUEK72N7I7KJ6JH |
| `shx-clear-flagslocked/stellar.toml` | https://stronghold.co/.well-known/stellar.toml |
| `shx-clear-flagslocked/blocked.json` | https://api.stellar.expert/explorer/directory/blocked-domains/stronghold.co |
| `shx-clear-flagslocked/directory.json` | https://api.stellar.expert/explorer/directory/GDSTRSHXHGJ7ZIVRBXEYE5Q74XUVCUSEKEBR7UCHEUUEK72N7I7KJ6JH |
| `usdc-revocable-regulated/asset.json` | https://horizon.stellar.org/assets?asset_code=USDC&asset_issuer=GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN |
| `usdc-revocable-regulated/account.json` | https://horizon.stellar.org/accounts/GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN |
| `usdc-revocable-regulated/stellar.toml.status` | https://circle.com/.well-known/stellar.toml (HTTP 404) |
| `usdc-revocable-regulated/blocked.json` | https://api.stellar.expert/explorer/directory/blocked-domains/circle.com |
| `usdc-revocable-regulated/directory.json` | https://api.stellar.expert/explorer/directory/GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN |
| `berkshire-clawback-scam/asset.json` | https://horizon.stellar.org/assets?asset_code=BERKSHIRE&asset_issuer=GA22QHSHQEHDJS2ZOINSC77XPPQ24G5EFRJGVEIZLKC5FAW3PQ5XNSDQ |
| `berkshire-clawback-scam/account.json` | https://horizon.stellar.org/accounts/GA22QHSHQEHDJS2ZOINSC77XPPQ24G5EFRJGVEIZLKC5FAW3PQ5XNSDQ |
| `berkshire-clawback-scam/stellar.toml.status` | https://nasdaq.finance/.well-known/stellar.toml (HTTP 000) |
| `berkshire-clawback-scam/blocked.json` | https://api.stellar.expert/explorer/directory/blocked-domains/nasdaq.finance |
| `berkshire-clawback-scam/directory.json` | https://api.stellar.expert/explorer/directory/GA22QHSHQEHDJS2ZOINSC77XPPQ24G5EFRJGVEIZLKC5FAW3PQ5XNSDQ |
| `doge-noflags-scam/asset.json` | https://horizon.stellar.org/assets?asset_code=DOGE&asset_issuer=GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P |
| `doge-noflags-scam/account.json` | https://horizon.stellar.org/accounts/GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P |
| `doge-noflags-scam/stellar.toml.status` | https://darkpool.digital/.well-known/stellar.toml (HTTP 000) |
| `doge-noflags-scam/blocked.json` | https://api.stellar.expert/explorer/directory/blocked-domains/darkpool.digital |
| `doge-noflags-scam/directory.json` | https://api.stellar.expert/explorer/directory/GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P |
| `velo-no-home-domain/asset.json` | https://horizon.stellar.org/assets?asset_code=VELO&asset_issuer=GDM4RQUQQUVSKQA7S6EM7XBZP3FCGH4Q7CL6TABQ7B2BEJ5ERARM2M5M |
| `velo-no-home-domain/account.json` | https://horizon.stellar.org/accounts/GDM4RQUQQUVSKQA7S6EM7XBZP3FCGH4Q7CL6TABQ7B2BEJ5ERARM2M5M |
| `velo-no-home-domain/directory.json` | https://api.stellar.expert/explorer/directory/GDM4RQUQQUVSKQA7S6EM7XBZP3FCGH4Q7CL6TABQ7B2BEJ5ERARM2M5M |

`velo-no-home-domain` is the subject issue #3 asks for: an issuer whose account
carries no `home_domain` at all. Verified live on 2026-09-28 that Horizon
**omits the field entirely** for this account rather than returning `""`, so
`account.json` deliberately has no `home_domain` key. The account has no
home domain, so no `stellar.toml` or `blocked.json` exists for it — the scan
does not fetch either for an account that advertised nothing
(`internal/scan/scan.go`).
