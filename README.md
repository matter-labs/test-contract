# Test data generator for the era-zkevm_test_harness

This repo generates the test artifacts for the [basic test](https://github.com/matter-labs/era-zkevm_test_harness/blob/v1.5.0/src/tests/complex_tests/test_artifacts/basic_test.json) of the era-zkevm_test_harness repository.

To generate the test data do the following:

1. Checkout era-contracts, and make sure to compile system-contracts

```
cd ../era-contracts && yarn sc build
```

2. Generate `predeployed_contracts_artifacts.json` file 

```
 SYSTEM_CONTRACTS_DIR=../anvil-zksync/contracts/system-contracts   yarn collect-system-contract
```


3. Run 

```
yarn build
```

The generated artifacts will be available in the `test_artifacts/basic_test.json` file.
