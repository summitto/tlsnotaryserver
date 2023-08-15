module github.com/summitto/tlsnotaryserver

go 1.18

replace notary => ./
replace github.com/summitto/ot-wrapper => ./softspoken

require (
	github.com/bwesterb/go-ristretto v1.2.1
	github.com/roasbeef/go-go-gadget-paillier v0.0.0-20181009074315-14f1f86b6000
	golang.org/x/crypto v0.0.0-20220513210258-46612604a0f9
	notary v0.0.0-00010101000000-000000000000
)

require golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
