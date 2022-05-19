import deployERC20 from './erc20/deploy.mjs'
import benchERC20 from './erc20/bench.mjs'
import { ethers } from 'ethers'
import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import { NonceManager } from "@ethersproject/experimental";
import benchBase from './base/bench.mjs'

const argv = yargs(hideBin(process.argv))

    .command('deploy-erc20', 'Deploys the ERC20 contract and returns the address it\'s deployed to')
    .command('bench-erc20', 'Benchmarks ERC20 token transfers', {
        contractAddress: {
            description: 'The contract address of the ERC20 to benchmark',
            type: 'string',
        },
        parallelism: {
            description: 'Number of wallet pairs to exchange tokens between in parallel',
            type: 'number',
        }
    })
    .command('bench-base', 'Benchmarks base token transfers')
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
const privateKey1 = argv.privateKey1 ?? "0x32a49a8408806e7a2862bca482c7aabd27e846f673edc8fb14501cab0d1d8ebe"
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
    const parallelism = argv.parallelism ?? 1
    await benchERC20(contractAddress, wallet1, rpc, parallelism, shouldContinue)
} else if (argv._.includes('bench-base')) {
    await benchBase(wallet1, rpc)
}
