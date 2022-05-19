import { ethers, Wallet } from 'ethers';

const NUM_PAIRS = 20

const benchBase = async (wallet1, rpc) => {
    console.log(`Creating ${NUM_PAIRS * 2} random wallets`)

    const wallets = [...Array(NUM_PAIRS * 2).keys()].map((k) => {
        const provider = new ethers.providers.JsonRpcProvider(rpc);
        return Wallet.createRandom().connect(provider)
    });

    console.log(`Dispensing tokens to all ${NUM_PAIRS * 2} random wallets`)
    const txs = []
    for (const w of wallets) {
        let tx = {value: 5000, to: w.address}
        let signPromise = wallet1.signTransaction(tx).then((signed_tx) => {
            return wallet1.provider.sendTransaction(signed_tx);
        })
        txs.push(await signPromise)
    }

    console.log(txs[0]);

    await Promise.all(txs.map(t => t.wait()))
    console.log(`Ready to go!`)
}


export default benchBase;