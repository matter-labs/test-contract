import '@typechain/hardhat';
import "@matterlabs/hardhat-zksync-node";
import '@matterlabs/hardhat-zksync-solc';


const COMPILER_VERSION = "1.5.7";
function getZksolcUrl(): string {
    // @ts-ignore
    const platform = { darwin: "macosx", linux: "linux", win32: "windows" }[process.platform];
    // @ts-ignore
    const toolchain = { linux: "-musl", win32: "-gnu", darwin: "" }[process.platform];
    const arch = process.arch === "x64" ? "amd64" : process.arch;
    const ext = process.platform === "win32" ? ".exe" : "";

    return `https://github.com/matter-labs/era-compiler-solidity/releases/download/${COMPILER_VERSION}/zksolc-${platform}-${arch}${toolchain}-v${COMPILER_VERSION}${ext}`;
}

export default {
    zksolc: {
        compilerSource: "binary",
        settings: {
            compilerPath: getZksolcUrl(),
            isSystem: true,
        },
    },
    zkSyncDeploy: {
        zkSyncNetwork: "http://localhost:3050",
        ethNetwork: "http://localhost:8545",
    },
    solidity: {
        version: '0.8.24',
        settings: {
            evmVersion: 'cancun'
        }
    },
    paths: {
        sources: './contracts'
    },
    networks: {
        hardhat: {
            zksync: true
        },
        zkSyncTestNode: {
            url: "http://127.0.0.1:8011",
            ethNetwork: "localhost",
            zksync: true,
        },
    }
};
