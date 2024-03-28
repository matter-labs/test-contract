import { ethers } from 'ethers';
import * as fs from 'fs';

interface PredeployedContractsArtifacts {
    predeployed_contracts: {
      [address: string]: string;
    };
    default_account_code: string;
}

interface TestArtifact {
    predeployed_contracts: {
        [address: string]: number[][];
    };
    default_account_code: number[][];
    entry_point_address: string;
    entry_point_code: number[][];
}

// An arbitrary user space address 
const TEST_CONTRACT_ADDRESS = '0xc54E30ABB6a3eeD1b9DC0494D90c9C22D76FbA7e';

// era-zkevm_test_harness expects that all bytecodes are of format `Vec<[u8; 32]>`, in other words, they need to be:
// - Arraified
// - Split into 32-byte chunks   
function splitIntoWords(bytecode: string): number[][] {
    const unpaddedBytecode = bytecode.substring(2);

    if(unpaddedBytecode.length % 64 !== 0) {
        throw new Error('Bytecode length is not a multiple of 64');
    }

    const words: number[][] = [];
    for (let i = 0; i < unpaddedBytecode.length; i += 64) {
        const bytes = ethers.utils.arrayify('0x' + unpaddedBytecode.substring(i, i + 64));


        words.push(Array.from(bytes));
    }
    return words;
}

async function main() {
    console.log(`Generate zkEVM test harness artifacts`);

    const predeployedContractArtifacts = JSON.parse(await fs.promises.readFile(`./predeployed_contracts_artifacts.json`, { encoding: 'utf-8' }) as string) as PredeployedContractsArtifacts;
    const testContractByrecode = JSON.parse(await fs.promises.readFile('./artifacts-zk/contracts/basic_test/Main.sol/Main.json', { encoding: 'utf-8' }) as string).bytecode as string;

    const predeployedContracts = {};
    for(const [address, bytecode] of Object.entries(predeployedContractArtifacts.predeployed_contracts)) {
        // @ts-ignore
        predeployedContracts[address] = splitIntoWords(bytecode);
    }

    const finalArtifact: TestArtifact = {
        predeployed_contracts: predeployedContracts,
        default_account_code: splitIntoWords(predeployedContractArtifacts.default_account_code),
        entry_point_address: TEST_CONTRACT_ADDRESS,
        entry_point_code: splitIntoWords(testContractByrecode),
    };

    await fs.promises.writeFile('./test_artifacts/basic_test.json', JSON.stringify(finalArtifact));
}

main()
    .then(() => process.exit(0))
    .catch((err) => {
        console.error('Error:', err.message || err);
        process.exit(1);
    });
