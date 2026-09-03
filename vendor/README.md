# cdoc2-cli

Download the latest CLI client from:
https://github.com/open-eid/cdoc2-java-ref-impl/packages/2223169
and save it as `cdoc2-cli.jar`.

## truststore.jks

Run from this directory:

```sh
openssl s_client -connect cdoc2.id.ee:8443 -showcerts </dev/null 2>/dev/null \
  | awk '/BEGIN CERT/{c=""} {c=c $0 ORS} /END CERT/{last=c} END{printf "%s", last}' > ca.pem

keytool -importcert -noprompt -trustcacerts -alias cdoc2-ca -file ca.pem \
  -keystore truststore.jks -storetype JKS -storepass passwd
```

Verify:

```sh
keytool -list -keystore truststore.jks -storepass passwd
```
