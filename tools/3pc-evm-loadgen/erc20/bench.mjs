import { ethers, Wallet } from 'ethers';
import fs from 'fs';
import sleep from 'await-sleep';
import { ERC20 } from './factory.mjs';
import { hrtime } from 'process';
import { NonceManager } from "@ethersproject/experimental";

const NUM_PAIRS = 20

const benchERC20 = async (contractAddress, wallet1, rpc, shouldContinue) => {
    let from1 = true;
    const tokenOwner = await ERC20(wallet1, contractAddress);
    console.log(`Creating ${NUM_PAIRS * 2} random wallets`)

        const provider = new ethers.providers.StaticJsonRpcProvider(rpc);
        return Wallet.createRandom().connect(provider)
    });

    const signers = wallets.map((w) => new NonceManager(w))

    const ercClients = await Promise.all(signers.map((signer) => {
        return ERC20(signer, contractAddress)
    }))

    console.log(`Dispensing tokens to all ${NUM_PAIRS * 2} random wallets`)
    const txs = []
    for (const erc of ercClients) {
        txs.push(await tokenOwner.transfer(erc.address, 5000))
    }

    await Promise.all(txs.map(t => t.wait()))
    console.log(`Ready to go!`)

    const tp_samples = await fs.createWriteStream("tp_samples.txt")
    const ts = hrtime();
    let tx_count = 0;
    while (shouldContinue()) {
        const txPromises = []
        for (let i = 0; i < NUM_PAIRS * 2; i+=2) {
            const erc = from1 ? ercClients[i] : ercClients[i + 1];
            const to = from1 ? wallets[i + 1].address : wallets[i].address;
            txPromises.push(erc.transfer(to, 5000));
        }

        const s = hrtime();
        const txs = await Promise.all(txPromises)
        await Promise.all(txs.map(tx => tx.wait()));
        const [es, ens] = hrtime(s)
        const ns = es * 1000000000 + ens
        await tp_samples.write(`${new Date().valueOf()}\t${ns}\n`.repeat(NUM_PAIRS))
        from1 = !from1;
        tx_count += NUM_PAIRS;
        const [ets, etns] = hrtime(ts)
        const tets = (ets + etns/1000000000)
        console.log(`TX/s: ${Math.floor(tx_count/tets*100)/100}`)
    }
    console.log("Done!")
    await tp_samples.close()
}


export default benchERC20;