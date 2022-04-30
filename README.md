# agent-rs

Since the ic-agent library relies on network libraries, random number libraries, etc., these libraries do not support compiling to Wasm. And the ic-agent need the private key to construct the new agent, and in the tECDSA, the private key cannot be obtained, there is only one signing interface. Therefore, ic-agent cannot be used directly.

However, to sign an update call using tECDSA, you need to encode the data required by the [Interface Specification](https://smartcontracts.org/docs/interface-spec/index.html), which is already well implemented in ic-agent.

So according to the ic-agent to extract a library that can be used in the wasm scene.