FROM alpine:3.13.0

RUN apk add git && apk add --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community go=1.18.1-r1

WORKDIR /go/src/github.com/summitto/tlsnotaryserver
COPY . .

WORKDIR /go/src/github.com/summitto/tlsnotaryserver/src
RUN go mod init notary
RUN go get github.com/bwesterb/go-ristretto@b51b4774df9150ea7d7616f76e77f745a464bbe3
RUN go get github.com/roasbeef/go-go-gadget-paillier@14f1f86b60008ece97b6233ed246373e555fc79f
RUN go get golang.org/x/crypto/blake2b
RUN go get golang.org/x/crypto/salsa20/salsa
RUN go build -o notary


# expose and run server
EXPOSE 10011/tcp
ENTRYPOINT ["./notary", "--no-sandbox"]
