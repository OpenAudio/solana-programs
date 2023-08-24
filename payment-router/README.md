# Payment Router

This program transfers SOL AUDIO or SOL USDC from its PDA token account to given recipients.

The program has a PDA (Program Derived Address) account that will own the tokens.

Please note that this program and its Anchor tests are set up to only work with the Solana mainnet cluster at the moment.

Here is the [deployed program](https://explorer.solana.com/address/6pca6uGGV5GYKY8W9aGfJbWPx4pe5mW8wLaP9c3LUNpp).

## Versions

Solana 1.16.1

```
solana-install init 1.16.1
solana -V
```

rustc 1.70.0

```
rustup install 1.70.0
rustup default 1.70.0
rustc -V
```

Node 18

```
nvm use
```

## Building

Make sure you have `anchor` installed. See https://www.anchor-lang.com/docs/installation. If you follow the installation steps, you should also have Rust, Solana, and Yarn installed.

Build the project.

```
anchor build
```

Anchor uses Yarn, so please sure you have it installed, and run

```
yarn install
```

## Unit tests

```
cargo test-sbf
```

## Integration tests

### Setting up your Solana cluster and environment

We are going to be invoking programs on the Solana mainnet.
So, for convenience, you can configure your cluster to use the Solana mainnet by default, and also use your chosen keypair file as the default Solana account by running:

```
./scripts/setupTestEnv.sh <fee-payer-keypair-file>
```

For example,

```
./scripts/setupTestEnv.sh id.json
```

### Testing the PDA creation

Note that the PDA has already been created, so attempting to create it again will fail. Here is [the PDA account](https://explorer.solana.com/address/67EAQXgyWFzWWDuxwkZjV4FdH4rQ2AidBp5iB4M4kWth).

```
./scripts/testCreatePaymentRouterBalancePda.sh
```

### Testing the Wormhole transfer

This will send 0.00001 AUDIO tokens to the wormhole for a given recipient to subsequently redeem.

```
./scripts/testRoute.sh
```
