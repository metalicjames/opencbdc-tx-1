import { promises as fs } from 'fs';
import path, { dirname } from 'path';
import { fileURLToPath } from 'url';
import { ethers } from 'ethers';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const ERC20Factory = async (wallet) => {
    const tokenContractJSON = await fs.readFile(path.join(__dirname, "Token.json"))
    const tokenContract = await JSON.parse(tokenContractJSON);
    const abi = new ethers.utils.Interface(tokenContract.abi).format(ethers.utils.FormatTypes.full);
    return new ethers.ContractFactory(abi, tokenContract.bytecode, wallet);
}

const ERC20 = async(wallet, contractAddress) => {
    const tokenContractJSON = await fs.readFile(path.join(__dirname, "Token.json"))
    const tokenContract = await JSON.parse(tokenContractJSON);
    const abi = new ethers.utils.Interface(tokenContract.abi).format(ethers.utils.FormatTypes.full);
    return new ethers.Contract(contractAddress, abi, wallet);
}

export {ERC20, ERC20Factory};