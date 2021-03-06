import { store } from "./App";
// import * as ethers from "ethers";
const bip39 = require('bip39')
const hdkey = require('ethereumjs-wallet/hdkey')

export async function createWallet(web3) {
  console.log("Creating new random wallet");
  const mnemonic = bip39.generateMnemonic()
  const wallet = await hdkey.fromMasterSeed(mnemonic).getWallet()
  console.log("Address generated:", wallet.getAddressString())
  // const wallet = await web3.eth.accounts.create()
  localStorage.setItem("mnemonic", mnemonic);
  localStorage.setItem("privateKey", wallet.getPrivateKeyString());
  return wallet
}

export async function findOrCreateWallet(web3) {
  //let privateKey = localStorage.getItem("privateKey");
  let mnemonic = localStorage.getItem("mnemonic")
  let wallet;
  if (mnemonic) {
    wallet = await hdkey.fromMasterSeed(mnemonic).getWallet()
    console.log("found existing wallet:", wallet.getAddressString());
  } else {
    wallet = await createWallet(web3);
  }
  store.dispatch({
    type: "SET_WALLET",
    text: wallet //Buffer.from(String(privKey.private),'hex')
  });
  return wallet;
}

export async function createWalletFromKey(privKey) {
  let wallet;
  // const wallet = new ethers.Wallet(privKey);
  //const wallet = new Wallet.fromPrivateKey(privKey)
  try{
    wallet = await hdkey.fromMasterSeed(privKey).getWallet()
    console.log(`Found wallet from mnemonic`)
    store.dispatch({
      type: "SET_WALLET",
      text: wallet //Buffer.from(String(privKey.private),'hex')
    });
    return wallet;
  }catch(e){
    console.log(`error in WalletGen`)
  }
}

export function getStore() {
  if (store) {
    return store;
  } else {
    console.log("no store found");
  }
}
