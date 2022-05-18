# 3PC/EVM Load generator

This folder contains the load generator for 3PC/EVM in NodeJS.

Run this to get started:

```
npm install -g pnpm
pnpm install
```

## Deploy ERC-20 token contract

You can deploy the ERC20 contract by running 

```
pnpm run deploy-erc20
```

It will output the address at which the contract is deployed.

You can specify your own privateKey1 (receives 1M tokens) and RPC endpoint through the command line, like so:

```
pnpm run deploy-erc20 --privateKey1 <key> --rpc <endpoint>
```

## Run ERC-20 token benchmark

You can benchmark the ERC20 contract by running

```
pnpm run bench-erc20 --contractAddress <address>
```

where `<address>` is the address of the deployed token contract

You can specify your own privateKey1 (first one to send) and privateKey2 (first one to receive) and RPC endpoint through the command line, like so:

`pnpm run deploy-erc20 --privateKey1 <key> --privateKey2 <key> --rpc <endpoint>`

If you've specified a distinct privateKey1 when deploying the ERC20, you should use the same key for bench-erc20 since it'll be the only key owning any tokens.

the benchmark will send tokens back and forth between the two addresses as fast as it can and write the completed transactions and their latencies to `tp_samples.txt`.

## Recompile the token contract

`erc20/Token.json` contains the pre-compiled token contract. The contract source is in `contracts/ERC20.sol`. You can recompile the contract by running `npx hardhat compile` and then copying the `Token.json` from the created `artifacts` folder.

