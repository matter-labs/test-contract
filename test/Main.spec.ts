import * as hre from "hardhat";
import { Wallet, Provider, ContractFactory } from "zksync-ethers";
import { Deployer } from "@matterlabs/hardhat-zksync-deploy";
import { ethers } from "ethers";

const RICH_WALLET_PK = "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110";
const COMPLEX_UPGRADER_ADDRESS = "0x0000000000000000000000000000000000000006";

async function prepareEnvironment(wallet: Wallet) {
  // For the purpose of the test we need to publish the code of the complex upgrader system contract.
  // By default during genesis of the test-node, the system contracts' bytecodes are not set as known. 
  // In zkevm test harness it will be set as known. In the future we will have a way to set the bytecode 
  // of the system contracts as "known" in the genesis.
  const code = await wallet.provider.getCode(COMPLEX_UPGRADER_ADDRESS);
  await (await wallet.sendTransaction({
    to: ethers.constants.AddressZero,
    customData: {
      factoryDeps: [code]
    }
  })).wait();
}

describe("Main test", function () {
  it("Main should work correctly", async function () {
    const provider = new Provider((hre.network.config as any).url);
    const wallet = new Wallet(RICH_WALLET_PK, provider);
    await prepareEnvironment(wallet);

    const deployer = new Deployer(hre, wallet);

    const artifact = await deployer.loadArtifact("Main");

    const factory = new ContractFactory(
      [],
      artifact.bytecode,
      wallet
    );
    const mainContract = await factory.deploy();
    await (
        await wallet.sendTransaction({
            to: mainContract.address,
            value: 1000
        })
    ).wait();
  });
});
