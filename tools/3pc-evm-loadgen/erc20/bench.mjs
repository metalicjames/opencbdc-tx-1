import { ethers } from 'ethers';
import fs from 'fs';
import sleep from 'await-sleep';
import { ERC20 } from './factory.mjs';
import { hrtime } from 'process';

const benchERC20 = async (contractAddress, wallet1, wallet2, shouldContinue) => {
    let from1 = true;
    const erc1 = await ERC20(wallet1, contractAddress);
    const erc2 = await ERC20(wallet2, contractAddress);

    const tp_samples = await fs.createWriteStream("tp_samples.txt")
    while (shouldContinue()) {
        const erc = from1 ? erc1 : erc2;
        const to = from1 ? wallet2.address : wallet1.address;
        const s = hrtime();
        const tx = await erc.transfer(to, 5000);
        await tx.wait();
        const [es, ens] = hrtime(s)
        const ns = es * 1000000000 + ens
        await tp_samples.write(`${new Date().valueOf()}\t${ns}\n`)
        from1 = !from1;
    }
    console.log("Done!")
    await tp_samples.close()
}


export default benchERC20;