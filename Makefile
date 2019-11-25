build:
	go build -o bin/pgpd pgpd.go

build-linux:
	CGO_ENABLED=0 GOOS=linux go build -o bin/pgpd pgpd.go
