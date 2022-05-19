import deployERC20 from './erc20/deploy.mjs'
import benchERC20 from './erc20/bench.mjs'
import { ethers } from 'ethers'
import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import { NonceManager } from "@ethersproject/experimental";

const argv = yargs(hideBin(process.argv))

    .command('deploy-erc20', 'Deploys the ERC20 contract and returns the address it\'s deployed to')
    .command('bench-erc20', 'Benchmarks ERC20 token transfers', {
        contractAddress: {
            description: 'The contract address of the ERC20 to benchmark',
            type: 'string',
        },
    })
    .option('rpc', {
        description: 'RPC Endpoint to talk to',
        type: 'string'
    })
    .option('privateKey1', {
        description: 'Private key 1 to use',
        type: 'string'
    })
    .help()
    .alias('help', 'h').argv;

const rpc = argv.rpc ?? "http://localhost:8080/"
const privateKey1 = argv.privateKey1 ?? "0xc904c738c315f2cb1d551baf7a01b3c163a68c502bf989b12c0d034fef26785e"
const contractAddress = argv.contractAddress

const provider1 = new ethers.providers.StaticJsonRpcProvider(rpc);
const wallet1 = new NonceManager(newethers.Wallet(privateKey1, provider1));

let run = true;

let shouldContinue = () => { return run; }

process.on('SIGINT', () => { run = false; })

if (argv._.includes('deploy-erc20')) {
    await deployERC20(wallet1)
} else if (argv._.includes('bench-erc20')) {
    if(!argv.contractAddress) {
        console.error("Please specify the address of the ERC20 contract to benchmark")
        process.exit(-1)
    }
    await benchERC20(contractAddress, wallet1, rpc, shouldContinue)
}
