import { ethers, Wallet } from 'ethers';
import fs from 'fs';
import sleep from 'await-sleep';
import { ERC20 } from './factory.mjs';
import { hrtime } from 'process';
import { NonceManager } from "@ethersproject/experimental";

const benchERC20 = async (contractAddress, wallet1, rpc, parallelism, shouldContinue) => {
    let from1 = true;
    const tokenOwner = await ERC20(wallet1, contractAddress);
    console.log(`Creating ${parallelism * 2} random wallets`)

    const wallets = [...Array(parallelism * 2).keys()].map((k) => {
        const provider = new ethers.providers.StaticJsonRpcProvider(rpc);
        return Wallet.createRandom().connect(provider)
    });

    const signers = wallets.map((w) => new NonceManager(w))

    const ercClients = await Promise.all(signers.map((signer) => {
        return ERC20(signer, contractAddress)
    }))

    console.log(`Dispensing tokens to all ${parallelism * 2} random wallets`)
    const txs = []
    for (const erc of ercClients) {
        txs.push(await tokenOwner.transfer(erc.address, 5000, { gasLimit: 0xffffffff, maxFeePerGas: 0, maxPriorityFeePerGas: 0 }))
    }

    await Promise.all(txs.map(t => t.wait()))
    console.log(`Ready to go!`)

    const tp_samples = await fs.createWriteStream("tp_samples.txt")
    const ts = hrtime();
    let tx_count = 0;
    while (shouldContinue()) {
        const txPromises = []
        for (let i = 0; i < parallelism * 2; i += 2) {
            const erc = from1 ? ercClients[i] : ercClients[i + 1];
            const to = from1 ? wallets[i + 1].address : wallets[i].address;
            txPromises.push(erc.transfer(to, 5000, { gasLimit: 0xffffffff, maxFeePerGas: 0, maxPriorityFeePerGas: 0 }));
        }

        const s = hrtime();
        const txs = await Promise.all(txPromises)
        //await Promise.all(txs.map(tx => tx.wait()));
        const [es, ens] = hrtime(s)
        const ns = es * 1000000000 + ens
        await tp_samples.write(`${new Date().valueOf()}\t${ns}\n`.repeat(parallelism))
        from1 = !from1;
        console.log(`TX/s: ${Math.floor(parallelism / (es + ens / 1000000000) * 100) / 100}`)
    }
    console.log("Done!")
    await tp_samples.close()
}


export default benchERC20;