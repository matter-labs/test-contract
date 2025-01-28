import { ethers } from 'ethers';
import * as fs from 'fs';

interface PredeployedContractsArtifacts {
    predeployed_contracts: {
        [address: string]: string;
    };
    default_account_code: string;
}


async function getBytecodeForSystemContract(systemContract: string): Promise<string> {
    const systemContractsDir = process.env.SYSTEM_CONTRACTS_DIR;

    if (!systemContractsDir) {
        throw new Error('SYSTEM_CONTRACTS_DIR environment variable is not set');
    }

    const jsonPath = `${systemContractsDir}/artifacts-zk/contracts-preprocessed/${systemContract}.sol/${systemContract}.json`;
    const jsonContent = JSON.parse(await fs.promises.readFile(jsonPath, { encoding: 'utf-8' }) as string);
    const deployedBytecode = jsonContent.deployedBytecode;

    if (!deployedBytecode) {
        throw new Error('deployedBytecode field is missing in foo.json');
    }
    return deployedBytecode;
}

async function getBytecodeForPrecompile(precompile: string): Promise<string> {
    const systemContractsDir = process.env.SYSTEM_CONTRACTS_DIR;

    if (!systemContractsDir) {
        throw new Error('SYSTEM_CONTRACTS_DIR environment variable is not set');
    }

    const filePath = `${systemContractsDir}/contracts-preprocessed/precompiles/artifacts/${precompile}.yul.zbin`;

    const bytecodeBuffer = await fs.promises.readFile(filePath);
    const deployedBytecode = '0x' + bytecodeBuffer.toString('hex');
    return deployedBytecode;
}

async function main() {
    console.log(`collecting system contracts`);

    const addressToStringMap: { [address: string]: string } = {
        // bootloader not needed
        '0x8002': 'AccountCodeStorage',
        '0x8003': 'NonceHolder',
        '0x8004': 'KnownCodesStorage',
        '0x8006': 'ContractDeployer',
        // Force deployer not needed
        '0x8008': 'L1Messenger',
        '0x8009': 'MsgValueSimulator',
        '0x800a': 'L2BaseToken',
        '0x800b': 'SystemContext',
        '0x800c': 'BootloaderUtilities',
        '0x800e': 'Compressor',
    };

    const precompiles: { [address: string]: string } = {
        '0x1': 'Ecrecover',
        '0x2': 'SHA256',
        '0x5': 'Modexp',
        '0x6': 'EcAdd',
        '0x7': 'EcMul',
        '0x8': 'EcPairing',
        '0x100': 'P256Verify',
        '0x8010': 'Keccak256',
    };


    const predeployedContracts: { [address: string]: string } = {};

    for (const [address, contractName] of Object.entries(addressToStringMap)) {
        const bytecode = await getBytecodeForSystemContract(contractName);
        const paddedAddress = ethers.utils.hexZeroPad(ethers.utils.hexlify(parseInt(address)), 20);
        predeployedContracts[paddedAddress] = bytecode;
    }

    for (const [address, contractName] of Object.entries(precompiles)) {
        const bytecode = await getBytecodeForPrecompile(contractName);
        const paddedAddress = ethers.utils.hexZeroPad(ethers.utils.hexlify(parseInt(address)), 20);
        predeployedContracts[paddedAddress] = bytecode;
    }

    const finalArtifact: PredeployedContractsArtifacts = {
        predeployed_contracts: predeployedContracts,
        default_account_code: await getBytecodeForSystemContract('DefaultAccount')
    };

    await fs.promises.writeFile('predeployed_contracts_artifacts.json', JSON.stringify(finalArtifact, null, 2));

}

main()
    .then(() => process.exit(0))
    .catch((err) => {
        console.error('Error:', err.message || err);
        process.exit(1);
    });
