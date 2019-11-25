# pgpd - PGP Decrypt

Simple opinionated CLI for decrypting PGP files in a hurry without verification

```
$ pgpd -h
Usage of pgpd:
  -in string
        Input file (default "-")
  -out string
        Output file (default "-")
  -pass string
        Passphrase to decrypt private key
  -pkey string
        Private key file
```

## Example usage

Read data from file and write to file

```sh
$ pgpd -pkey key.asc -pass password -in encrypted.file.pgp -out decrypted.file
```

Decrypt data from STDIN and write to STDOUT

```sh
$ cat encrypted.file.pgp | pgpd -pkey key.asc -pass password > decrypted.file
```

Decrypt and gunzip file from GCS and write to disk

```
$ gsutil cat gs://bucket/encrypted.file.gz.pgp - | pgpd -pkey key.asc -pass password | gunzip > decrypted.file
```
