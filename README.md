# tlsnotaryserver

This is the notary server for the TLSNotary protocol.

It is primarily intended to be run inside a sandboxed AWS EC2 instance (https://github.com/tlsnotary/pagesigner-oracles). It can also be run as a regular server (you'll have to start it with --no-sandbox and pass the file public.key to the client).

## Prerequisites

- [MPC circuits](./tagCircuits/) unpack the files
- Node 16.14
- CMake 3.16+
- GCC 9+
- Python 3
- `ecdsa` 0.18.0 python library

## Setup

1. Make sure Node.js 16 LTS is installed in the system.
2. Install `ecdsa>=0.18.0b1` Python library

3. Clone this repo, then initialize submodules
`git submodule update --init --recursive`

4. Generate an ECDSA signing key in PEM format and save it to `signing.key`

    Example: `openssl ecparam -name secp256r1 -genkey -noout -out signing.key`

5. Generate keys of desired size
    1. Copy all circuits from ProveThis to some local directory.
    2. Create main circuit of desired size using [main_N.circom template](./main_N.circom.template). Replace `NUMBER_OF_AES_BLOCKS_HERE` with a number of AES blocks this circuit should be able to reveal.
    3. Compile the circuits: `circom ./path/to/main_N.circom --r1cs --O1 --output .`. This will create a `main_N.r1cs` file.
    4. Generate a proving key (needs snarkjs CLI): `snarkjs groth16 setup main_N.r1cs ./path/to/ptau/file.ptau N.zkey`. This will create a `N.zkey` proving key file.
    5. Export a verification key (needs snarkjs CLI): `snarkjs zkey export verificationkey N.zkey N.json`. This will create a `N.json` verification key file.
    6. Place `N.zkey` and `N.json` into `zkey-content` directory in your working directory.
    7. Repeat steps 2-6 for every N AES blocks you want to be able to prove, e.g. if you want to prove 1 AES block in one proof, and 4 AES blocks in another proof,
    you need to repeat those steps with N=1 and N=4

6. Compile:
    1. `cd src/aesmpc`, then build server according to README
    2. `cd src/softspoken`, then build Go wrapper according to README
    3. `cd ..`
    4. `CGO_LDFLAGS="-lcrypto -lssl -ldl -lpthread -laesmpc" go build -o notary`

7. Run on a local machine with:
`LD_LIBRARY_PATH=$(pwd)/src/aesmpc:$(pwd)/src/softspoken/pkg ./notary --no-sandbox`

## Public API endpoints

#### `/zkey_sizes`

Returns a list of supported ZK key pair sizes. For proving 1 AES block you need a key pair of size 1, and so on.

Example response:

```json
{
  "sizes": [1, 2]
}
```

#### `/zkey`

Returns a ZK key pair of required size if it exists on the server. The keys must be generated beforehand.

Required query params:
- `size` - key pair size - Example: `/zkey?size=1`

> **Note:** This endpoint uses chunked transfer limited to ~16MB/s

Example response:

```json
{
  "pk": "base64 string",
  "vk": "base64 string",
  "size": 1,
  "error": "optional, error message"
}
```

If a key pair of requested size doesn't exist, the endpoint will return 404 Not Found with an error message in JSON body

#### `/signing-key.pem`

Returns tag verification signing key in PEM format.

`Content-Type` header will be set to `application/x-pem-file`

Example response:

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvssE2tGCz8iN8Ppv9iuQPh3Wgrt7
SfwKK95seuhYF6kwXoEHRZ29uCQGVl43rJmlO8nDFH0gtqF/oaiwTLMjHA==
-----END PUBLIC KEY-----
```
