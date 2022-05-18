import {ERC20Factory} from './factory.mjs'

const deployERC20 = async (wallet) => {
    const factory = await ERC20Factory(wallet);
    let contract = await factory.deploy();
    await contract.deployed();
    console.log(contract.address);
}

export default deployERC20;
