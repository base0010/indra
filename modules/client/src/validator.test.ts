import { assert } from './testing/index'
import * as t from './testing/index'
import { Validator } from './validator';
import * as sinon from 'sinon'
import { Utils } from './Utils';
import {
  convertChannelState,
  convertPayment,
  ChannelEventReason,
  PaymentArgs,
  PaymentArgsBN,
  convertThreadState,
  UnsignedThreadState,
  ChannelStateBN,
  WithdrawalArgsBN,
  convertWithdrawal,
  ExchangeArgsBN,
  EmptyChannelArgs,
  EventInputs,
  PendingArgs,
  proposePendingNumericArgs,
  convertProposePending,
  PendingArgsBN,
  PendingExchangeArgsBN,
  InvalidationArgs,
  DepositArgsBN
} from './types';
import { toBN, mul } from './helpers/bn';
import Web3 = require('web3')
import { EMPTY_ROOT_HASH } from './lib/constants';
import { HttpProvider } from 'web3/providers';

const sampleAddr = "0x0bfa016abfa8f627654b4989da4620271dc77b1c"

const createMockedTxReceipt: { [name in ChannelEventReason]: (sender: "user" | "hub", web3: Web3, type?: "deposit" | "withdrawal", ...overrides: any[]) => any } = {
  DidEmptyChannel: (sender, web3, ...overrides: any[]) =>
    createMockedEmptyChannelTxReceipt(sender, web3, ...overrides)
  ,

  DidStartExitChannel: (sender, web3, ...overrides: any[]) =>
    createMockedStartExitChannelTxReceipt(sender, web3, ...overrides)
  ,

  DidUpdateChannel: (sender, web3, type, ...overrides: any[]) => {
    // default to deposit tx
    return createMockedUpdateChannelTxReceipt(
      sender,
      web3,
      type || "deposit",
      ...overrides
    )
  },
}

function createMockedEmptyChannelTxReceipt(sender: "user" | "hub", web3: Web3, ...overrides: any[]) {
  const vals = _generateTransactionReceiptValues({
    user: sampleAddr,
    senderIdx: sender === "user" ? '1' : '0', // default to user wei deposit 5,
    txCount: ["420", "69"],
  }, ...overrides)

  return _createMockedTransactionReceipt("DidEmptyChannel", web3, vals)
}

function createMockedStartExitChannelTxReceipt(sender: "user" | "hub", web3: Web3, ...overrides: any[]) {
  const vals = _generateTransactionReceiptValues({
    user: sampleAddr,
    senderIdx: sender === "user" ? '1' : '0', // default to user wei deposit 5,
    txCount: ["420", "69"],
  }, ...overrides)
  return _createMockedTransactionReceipt("DidStartExitChannel", web3, vals)
}

function createMockedUpdateChannelTxReceipt(sender: "user" | "hub", web3: Web3, type: "deposit" | "withdrawal", ...overrides: any[]) {
  switch (type) {
    case "deposit":
      return createMockedDepositTxReceipt(sender, web3, overrides)
    case "withdrawal":
      return createMockedWithdrawalTxReceipt(sender, web3, overrides)
    default:
      throw new Error('Unrecognized type:' + type)
  }
}

/* Overrides for these fns function must be in the contract format
as they are used in solidity decoding. Returns tx with default deposit
values of all 5s
*/
function createMockedWithdrawalTxReceipt(sender: "user" | "hub", web3: Web3, ...overrides: any[]) {
  const vals = _generateTransactionReceiptValues({
    senderIdx: sender === "user" ? '1' : '0', // default to user wei deposit 5
    pendingWeiUpdates: ['0', '5', '0', '5'],
    pendingTokenUpdates: ['0', '5', '0', '5'],
    txCount: ['4', '3']
  }, ...overrides)

  return _createMockedTransactionReceipt("DidUpdateChannel", web3, vals)
}

function createMockedDepositTxReceipt(sender: "user" | "hub", web3: Web3, ...overrides: any[]) {
  const vals = _generateTransactionReceiptValues({
    senderIdx: sender === "user" ? '1' : '0', // default to user wei deposit 5
    pendingWeiUpdates: ['5', '0', '5', '0'],
    pendingTokenUpdates: ['5', '0', '5', '0'],
  }, ...overrides)

  return _createMockedTransactionReceipt("DidUpdateChannel", web3, vals)
}

function _generateTransactionReceiptValues(...overrides: any[]) {
  return Object.assign({
    user: sampleAddr,
    senderIdx: '1', // default to user wei deposit 5
    weiBalances: ['0', '0'],
    tokenBalances: ['0', '0'],
    txCount: ['1', '1'],
    threadRoot: EMPTY_ROOT_HASH,
    threadCount: '0',
  }, ...overrides)
}

function _createMockedTransactionReceipt(event: ChannelEventReason, web3: Web3, vals: any) {
  const eventTopic = web3.eth.abi.encodeEventSignature({
    name: event,
    type: 'event',
    inputs: EventInputs[event],
  })

  const addrTopic = web3.eth.abi.encodeParameter('address', vals.user)

  // put non-indexed values in same order as types
  const nonIndexedTypes = EventInputs[event].filter(val => Object.keys(val).indexOf('indexed') === -1).map(e => e.type)
  let nonIndexedVals: any = []
  EventInputs[event].forEach(val => {
    if (val.indexed) {
      return
    }
    nonIndexedVals.push(vals[val.name])
  })

  const data = web3.eth.abi.encodeParameters(nonIndexedTypes, nonIndexedVals)

  return {
    status: true,
    contractAddress: t.mkAddress('0xCCC'),
    transactionHash: t.mkHash('0xHHH'),
    logs: [{
      data: web3.utils.toHex(data),
      topics: [eventTopic, addrTopic]
    }]
  }
}

function createPreviousChannelState(...overrides: t.PartialSignedOrSuccinctChannel[]) {
  const state = t.getChannelState('empty', Object.assign({
    user: sampleAddr,
    recipient: sampleAddr,
    sigUser: t.mkHash('booty'),
    sigHub: t.mkHash('errywhere'),
  }, ...overrides))
  return convertChannelState("bn", state)
}

function createThreadPaymentArgs(...overrides: Partial<PaymentArgs<any>>[]) {
  const { recipient, ...amts } = createPaymentArgs(...overrides)
  return amts
}

function createPaymentArgs(
  ...overrides: Partial<PaymentArgs<any>>[]
): PaymentArgsBN {
  const args = Object.assign({
    amountWei: '0',
    amountToken: '0',
    recipient: "user",
  }, ...overrides) as any

  return convertPayment("bn", { ...convertPayment("str", args) })
}

function createProposePendingArgs(overrides?: Partial<PendingArgs<number>>): PendingArgsBN {
  const res = {
    recipient: '0x1234',
    timeout: 0,
  } as PendingArgs
  proposePendingNumericArgs.forEach((a: string) => (res as any)[a] = 0)
  return convertProposePending('bn', {
    ...res,
    ...(overrides || {}),
  })
}

function createThreadState(...overrides: t.PartialSignedOrSuccinctThread[]) {
  let opts = Object.assign({}, ...overrides)
  const thread = t.getThreadState("empty", {
    sigA: t.mkHash('0xtipz'),
    balanceWei: [5, 0],
    balanceToken: [5, 0],
    receiver: t.mkAddress('0xAAA'),
    sender: sampleAddr,
    ...opts
  })
  return convertThreadState("bn", thread)
}

/*
 Use this function to create an arbitrary number of thread states as indicated by the targetThreadCount parameter. Override each thread state that gets returned with provided override arguments. Example usage and output:

 > createChannelThreadOverrides(2, { threadId: 87, receiver: t.mkAddress('0xAAA') })
 > { threadCount: 2,
  initialThreadStates:
   [ { contractAddress: '0xCCC0000000000000000000000000000000000000',
       sender: '0x0bfA016aBFa8f627654b4989DA4620271dc77b1C',
       receiver: '0xAAA0000000000000000000000000000000000000',
       threadId: 87,
       balanceWeiSender: '5',
       balanceWeiReceiver: '0',
       balanceTokenSender: '5',
       balanceTokenReceiver: '0',
       txCount: 0 },
     { contractAddress: '0xCCC0000000000000000000000000000000000000',
       sender: '0x0bfA016aBFa8f627654b4989DA4620271dc77b1C',
       receiver: '0xAAA0000000000000000000000000000000000000',
       threadId: 87,
       balanceWeiSender: '5',
       balanceWeiReceiver: '0',
       balanceTokenSender: '5',
       balanceTokenReceiver: '0',
       txCount: 0 } ],
  threadRoot: '0xbb97e9652a4754f4e543a7ed79b654dc5e5914060451f5d87e0b9ab1bde73bef' }
 */
function createChannelThreadOverrides(targetThreadCount: number, ...overrides: any[]) {
  const utils = new Utils()
  if (!targetThreadCount) {
    return {
      threadCount: 0,
      initialThreadStates: [],
      threadRoot: EMPTY_ROOT_HASH
    }
  }

  let initialThreadStates = [] as UnsignedThreadState[]
  for (let i = 0; i < targetThreadCount; i++) {
    initialThreadStates.push(convertThreadState("str-unsigned", createThreadState(Object.assign({
      receiver: t.mkAddress(`0x${i + 1}`),
      threadId: 69 + i,
    }, ...overrides)
    )))
  }
  return {
    threadCount: targetThreadCount,
    initialThreadStates,
    threadRoot: utils.generateThreadRootHash(initialThreadStates)
  }
}

describe('validator', () => {
  let web3 = new Web3() /* NOTE: all functional aspects of web3 are mocked */
  const validator = new Validator(web3, t.mkAddress('0xHHH'))

  describe('channelPayment', () => {
    const prev = createPreviousChannelState({
      balanceToken: [5, 5],
      balanceWei: [5, 5],
    })

    const paymentTestCases = [
      {
        name: 'valid hub to user payment',
        args: createPaymentArgs({
          amountToken: 1,
          amountWei: '1',
        }),
        valid: true
      },
      {
        name: 'valid user to hub payment',
        args: createPaymentArgs({ recipient: "hub" }),
        valid: true
      },
      {
        name: 'should return a string payment args are negative',
        args: createPaymentArgs({ amountToken: -1, amountWei: -1 }),
        valid: false,
      },
      {
        name: 'should return a string if payment exceeds available channel balance',
        args: createPaymentArgs({ amountToken: 10, amountWei: 10 }),
        valid: false,
      }
    ]

    paymentTestCases.forEach(({ name, args, valid }) => {
      it(name, () => {
        if (valid)
          assert.isNull(validator.channelPayment(prev, args))
        else
          assert.exists(validator.channelPayment(prev, args))
      })
    })
  })

  function getExchangeCases() {
    const prev = createPreviousChannelState({
      balanceToken: [5, 5],
      balanceWei: [5, 5],
    })

    let baseWeiToToken = {
      weiToSell: toBN(1),
      tokensToSell: toBN(0),
      exchangeRate: '5',
      seller: "user"
    }

    let baseTokenToWei = {
      weiToSell: toBN(0),
      tokensToSell: toBN(5),
      exchangeRate: '5',
      seller: "user"
    }

    return [
      {
        name: 'valid token for wei exchange seller is user',
        prev,
        args: baseTokenToWei,
        valid: true,
      },
      {
        name: 'valid token for wei exchange seller is hub',
        prev,
        args: { ...baseTokenToWei, seller: "hub" },
        valid: true,
      },
      {
        name: 'valid wei for token exchange seller is user',
        prev,
        args: baseWeiToToken,
        valid: true,
      },
      {
        name: 'valid wei for token exchange seller is user',
        prev,
        args: { ...baseWeiToToken, seller: "hub" },
        valid: true,
      },
      {
        name: 'should return a string if both toSell values are zero',
        prev,
        args: { ...baseWeiToToken, weiToSell: toBN(0) },
        valid: false,
      },
      {
        name: 'should return a string if neither toSell values are zero',
        prev,
        args: { ...baseWeiToToken, tokensToSell: toBN(1) },
        valid: false,
      },
      {
        name: 'should return a string if negative wei to sell is provided',
        prev,
        args: { ...baseWeiToToken, weiToSell: toBN(-5) },
        valid: false,
      },
      {
        name: 'should return a string if negative tokens to sell is provided',
        prev,
        args: { ...baseTokenToWei, tokensToSell: toBN(-5) },
        valid: false,
      },
      {
        name: 'should return a string if seller cannot afford tokens for wei exchange',
        prev,
        args: { ...baseTokenToWei, tokensToSell: toBN(10) },
        valid: false,
      },
      {
        name: 'should return a string if seller cannot afford wei for tokens exchange',
        prev,
        args: { ...baseWeiToToken, weiToSell: toBN(10) },
        valid: false,
      },
      {
        name: 'should return a string if payor cannot afford wei for tokens exchange',
        prev,
        args: { ...baseWeiToToken, weiToSell: toBN(2), },
        valid: false,
      },
      {
        name: 'should return a string if payor as hub cannot afford tokens for wei exchange',
        prev: { ...prev, balanceWeiHub: toBN(0) },
        args: { ...baseTokenToWei, weiToSell: toBN(10) },
        valid: false,
      },
      {
        name: 'should return a string if payor as user cannot afford tokens for wei exchange',
        prev: { ...prev, balanceWeiUser: toBN(0) },
        args: { ...baseTokenToWei, weiToSell: toBN(10), seller: "user" },
        valid: false,
      },
    ]
  }

  describe('exchange', () => {
    getExchangeCases().forEach(({ name, prev, args, valid }) => {
      it(name, () => {
        if (valid) {
          assert.isNull(validator.exchange(prev, args as ExchangeArgsBN))
        } else {
          assert.exists(validator.exchange(prev, args as ExchangeArgsBN))
        }
      })
    })
  })

  describe('proposePendingDeposit', () => {
    const prev = createPreviousChannelState({
      balanceToken: [5, 5],
      balanceWei: [5, 5]
    })
    const args: DepositArgsBN = {
      depositWeiHub: toBN(1),
      depositWeiUser: toBN(1),
      depositTokenHub: toBN(1),
      depositTokenUser: toBN(1),
      sigUser: t.mkHash('0xsigUser'),
      timeout: 6969,
    }

    const proposePendingDepositCases = [
      {
        name: 'should work',
        prev,
        args,
        valid: true
      },
      {
        name: 'should work if 0 timeout provided (hub authorized deposits)',
        prev,
        args: { ...args, timeout: 0 },
        valid: true
      },
      {
        name: 'should return a string if pending operations exist on the previous state',
        prev: { ...prev, pendingDepositWeiUser: toBN(5) },
        args,
        valid: false
      },
      {
        name: 'should return a string for negative deposits',
        prev,
        args: { ...args, depositWeiUser: toBN(-5) },
        valid: false
      },
      {
        name: 'should return a string if negative timeout provided',
        prev,
        args: { ...args, timeout: -5 },
        valid: false
      },
      {
        name: 'should fail if an invalid signer is provided',
        prev,
        args,
        valid: false,
        sigRecover: true,
      },
    ]

    proposePendingDepositCases.forEach(({ name, prev, args, valid, sigRecover = false }) => {
      it(name, () => {
        if (sigRecover) {
          console.log('validator will throw error')
          validator.assertDepositRequestSigner = (args: any, signer: string) => { throw new Error('Invalid signer') }
        } else {
          validator.assertDepositRequestSigner = (args: any, signer: string) => { return }
        }
        if (valid) {
          assert.isNull(validator.proposePendingDeposit(prev, args))
        } else {
          assert.exists(validator.proposePendingDeposit(prev, args))
        }
      })
    })
  })

  describe('proposePendingWithdrawal', () => {
    const prev: ChannelStateBN = createPreviousChannelState({
      balanceWei: [10, 5],
      balanceToken: [5, 10]
    })
    const args: WithdrawalArgsBN = convertWithdrawal("bn", t.getWithdrawalArgs("empty", {
      exchangeRate: '2',
      tokensToSell: 10,
      targetWeiUser: 0,
      targetWeiHub: 5,
    }))

    const withdrawalCases: { name: any, prev: ChannelStateBN, args: WithdrawalArgsBN, valid: boolean }[] = [
      {
        name: 'should work',
        prev,
        args,
        valid: true
      },
      {
        name: 'should return a string if there are pending ops in prev',
        prev: { ...prev, pendingDepositWeiUser: toBN(10) },
        args,
        valid: false
      },
      {
        name: 'should return a string if the args have a negative value',
        prev,
        args: { ...args, weiToSell: toBN(-5) },
        valid: false
      },
      {
        name: 'should return a string if resulting state has negative values',
        prev,
        args: { ...args, tokensToSell: toBN(20) },
        valid: false
      },
      {
        name: 'should return a string if the args result in an invalid transition',
        prev,
        args: { ...args, weiToSell: toBN(10), tokensToSell: toBN(0), additionalWeiHubToUser: toBN(30) },
        valid: false
      },
      // TODO: find out which args may result in this state from the
      // withdrawal function (if any) from wolever
      // {
      //   name: 'should return a string if hub collateralizes an exchange and withdraws with the same currency',
      //   prev,
      //   args: '',
      //   valid: false
      // },
    ]

    withdrawalCases.forEach(({ name, prev, args, valid }) => {
      it(name, () => {
        const res = validator.proposePendingWithdrawal(prev, args)
        if (valid) {
          assert.isNull(res)
        } else {
          assert.exists(res)
        }
      })
    })
  })

  describe('confirmPending', () => {
    const depositReceipt = createMockedDepositTxReceipt("user", web3)
    const wdReceipt = createMockedWithdrawalTxReceipt("user", web3)
    const multipleReceipt = { ...depositReceipt, logs: depositReceipt.logs.concat(wdReceipt.logs) }

    const prevDeposit = createPreviousChannelState({
      pendingDepositToken: [5, 5],
      pendingDepositWei: [5, 5],
    })
    const prevWd = createPreviousChannelState({
      pendingWithdrawalToken: [5, 5],
      pendingWithdrawalWei: [5, 5],
      recipient: t.mkAddress('0xAAA'),
      txCount: [4, 3]
    })

    const tx = {
      blockHash: t.mkHash('0xBBB'),
      to: prevDeposit.contractAddress,
    }

    const confirmCases = [
      {
        name: 'should work for deposits',
        prev: prevDeposit,
        stubs: [tx, depositReceipt],
        valid: true,
      },
      {
        name: 'should work for withdrawals',
        prev: prevWd,
        stubs: [tx, wdReceipt],
        valid: true,
      },
      {
        name: 'should work depsite casing differences',
        prev: { ...prevDeposit, user: prevDeposit.user.toUpperCase(), recipient: prevDeposit.user.toUpperCase() },
        stubs: [tx, depositReceipt],
        valid: true,
      },
      {
        name: 'should work if given multiple channel events in logs',
        prev: prevDeposit,
        stubs: [tx, multipleReceipt],
        valid: true,
      },
      {
        name: 'should return a string if no transaction is found with that hash',
        prev: prevWd,
        stubs: [null, depositReceipt],
        valid: false,
      },
      {
        name: 'should return a string if transaction is not sent to contract',
        prev: prevDeposit,
        stubs: [{ ...tx, to: t.mkAddress('0xfail') }, depositReceipt],
        valid: false,
      },
      {
        name: 'should return a string if transaction is not sent by participants',
        prev: { ...prevDeposit, user: t.mkAddress('0xUUU'), },
        stubs: [tx, depositReceipt],
        valid: false,
      },
      {
        name: 'should return a string if user is not same in receipt and previous',
        prev: { ...prevDeposit, user: t.mkAddress('0xUUU'), },
        stubs: [tx, createMockedDepositTxReceipt("hub", web3)],
        valid: false,
      },
      // {
      //   name: 'should return a string if balance wei hub is not same in receipt and previous',
      //   prev: { ...prevDeposit, balanceWeiHub: toBN(5) },
      //   stubs: [tx, depositReceipt],
      //   valid: false,
      // },
      // {
      //   name: 'should return a string if balance wei user is not same in receipt and previous',
      //   prev: { ...prevDeposit, balanceWeiUser: toBN(5) },
      //   stubs: [tx, depositReceipt],
      //   valid: false,
      // },
      // {
      //   name: 'should return a string if balance token hub is not same in receipt and previous',
      //   prev: { ...prevDeposit, balanceTokenHub: toBN(5) },
      //   stubs: [tx, depositReceipt],
      //   valid: false,
      // },
      // {
      //   name: 'should return a string if balance token user is not same in receipt and previous',
      //   prev: { ...prevDeposit, balanceTokenUser: toBN(5) },
      //   stubs: [tx, depositReceipt],
      //   valid: false,
      // },
      {
        name: 'should return a string if pending deposit wei hub is not same in receipt and previous',
        prev: { ...prevDeposit, pendingDepositWeiHub: toBN(3) },
        stubs: [tx, depositReceipt],
        valid: false,
      },
      {
        name: 'should return a string if pending deposit wei user is not same in receipt and previous',
        prev: { ...prevDeposit, pendingDepositWeiUser: toBN(3) },
        stubs: [tx, depositReceipt],
        valid: false,
      },
      {
        name: 'should return a string if pending deposit token hub is not same in receipt and previous',
        prev: { ...prevDeposit, pendingDepositTokenHub: toBN(3) },
        stubs: [tx, depositReceipt],
        valid: false,
      },
      {
        name: 'should return a string if pending deposit token user is not same in receipt and previous',
        prev: { ...prevDeposit, pendingDepositTokenUser: toBN(3) },
        stubs: [tx, depositReceipt],
        valid: false,
      },
      {
        name: 'should return a string if pending withdrawal wei hub is not same in receipt and previous',
        prev: { ...prevWd, pendingWithdrawalWeiHub: toBN(10) },
        stubs: [tx, wdReceipt],
        valid: false,
      },
      {
        name: 'should return a string if pending withdrawal wei user is not same in receipt and previous',
        prev: { ...prevWd, pendingWithdrawalWeiUser: toBN(10) },
        stubs: [tx, wdReceipt],
        valid: false,
      },
      {
        name: 'should return a string if pending withdrawal token hub is not same in receipt and previous',
        prev: { ...prevWd, pendingWithdrawalTokenHub: toBN(10) },
        stubs: [tx, wdReceipt],
        valid: false,
      },
      {
        name: 'should return a string if pending withdrawal token user is not same in receipt and previous',
        prev: { ...prevWd, pendingWithdrawalTokenUser: toBN(10) },
        stubs: [tx, wdReceipt],
        valid: false,
      },
      // {
      //   name: 'should return a string if tx count global is not same in receipt and previous',
      //   prev: { ...prevDeposit, txCountGlobal: 7 },
      //   stubs: [tx, depositReceipt],
      //   valid: false,
      // },
      {
        name: 'should return a string if tx count chain is not same in receipt and previous',
        prev: { ...prevDeposit, txCountChain: 7 },
        stubs: [tx, depositReceipt],
        valid: false,
      },
      // {
      //   name: 'should return a string if thread root is not same in receipt and previous',
      //   prev: { ...prevDeposit, threadRoot: t.mkHash('0xROOTZ') },
      //   stubs: [tx, depositReceipt],
      //   valid: false,
      // },
      // {
      //   name: 'should return a string if thread count is not same in receipt and previous',
      //   prev: { ...prevDeposit, threadCount: 7 },
      //   stubs: [tx, depositReceipt],
      //   valid: false,
      // },
    ]

    confirmCases.forEach(async ({ name, prev, stubs, valid }) => {
      it(name, async () => {
        // set tx receipt stub
        validator.web3.eth.getTransaction = sinon.stub().returns(stubs[0])
        validator.web3.eth.getTransactionReceipt = sinon.stub().returns(stubs[1])
        // set args
        const transactionHash = stubs[1] && (stubs[1] as any).transactionHash === depositReceipt.transactionHash ? depositReceipt.transactionHash : wdReceipt.transactionHash
        if (valid) {
          assert.isNull(await validator.confirmPending(prev, { transactionHash }))
        } else {
          assert.exists(await validator.confirmPending(prev, { transactionHash }))
        }
      })
    })
  })

  describe('invalidation', () => {
    const prev = createPreviousChannelState({
      txCount: [1, 1]
    })

    const args: InvalidationArgs = {
      previousValidTxCount: prev.txCountGlobal,
      lastInvalidTxCount: prev.txCountGlobal + 1,
      reason: "CU_INVALID_ERROR",
    }

    const invalidationCases = [
      {
        name: 'should work',
        prev,
        args,
        valid: true
      },
      {
        name: 'should return string if previous nonce is higher than nonce to be invalidated',
        prev,
        args: { ...args, previousValidTxCount: 3 },
        valid: false
      },
      {
        name: 'should return string if previous state nonce and nonce in args do not match',
        prev: { ...prev, txCountGlobal: 5 },
        args: { ...args, previousValidTxCount: 3, lastInvalidTxCount: 3 },
        valid: false
      },
      {
        name: 'should return string if previous state has pending ops',
        prev: { ...prev, pendingDepositWeiUser: toBN(5) },
        args,
        valid: false
      },
      {
        name: 'should return string if previous state is missing sigHub',
        prev: { ...prev, sigHub: '' },
        args,
        valid: false
      },
      {
        name: 'should return string if previous state is missing sigUser',
        prev: { ...prev, sigUser: '' },
        args,
        valid: false
      },
    ]

    invalidationCases.forEach(({ name, prev, args, valid }) => {
      it(name, () => {
        if (valid) {
          assert.isNull(validator.invalidation(prev, args))
        } else {
          assert.exists(validator.invalidation(prev, args))
        }
      })
    })
  })

  describe('emptyChannel', () => {
    const emptyReceipt = createMockedTxReceipt.DidEmptyChannel("user", web3)
    const nonzeroReceipt = createMockedTxReceipt.DidEmptyChannel("user", web3, undefined, { weiBalances: ["1", "0"] })
    const depositReceipt = createMockedDepositTxReceipt("user", web3)

    const multipleReceipt = { ...emptyReceipt, logs: emptyReceipt.logs.concat(depositReceipt.logs) }

    const prev = createPreviousChannelState({
      txCount: [420, 69],
    })

    const args: EmptyChannelArgs = {
      transactionHash: emptyReceipt.transactionHash,
    }

    const tx = {
      blockHash: t.mkHash('0xBBB'),
      to: prev.contractAddress,
    }

    const emptyChannelCases = [
      {
        name: "should work",
        prev,
        args,
        stubs: [tx, emptyReceipt],
        valid: true,
      },
      {
        name: "should work with multiple events",
        prev,
        args,
        stubs: [tx, multipleReceipt],
        valid: true,
      },
      {
        name: "should fail if it cannot find tx",
        prev,
        args,
        stubs: [null, emptyReceipt],
        valid: false,
      },
      {
        name: "should fail if tx has no blockhash",
        prev,
        args,
        stubs: [{ ...tx, blockHash: null }, emptyReceipt],
        valid: false,
      },
      {
        name: "should fail if tx to contract not found",
        prev: { ...prev, contractAddress: t.mkAddress('0xfail') },
        args,
        stubs: [tx, emptyReceipt],
        valid: false,
      },
      {
        name: "should fail if no event is found",
        prev,
        args,
        stubs: [tx, { ...emptyReceipt, logs: null }],
        valid: false,
      },
      {
        name: "should fail if no matching event is found",
        prev: { ...prev, user: t.mkAddress('0xfail') },
        args,
        stubs: [tx, emptyReceipt],
        valid: false,
      },
      {
        name: "should fail if event has nonzero fields",
        prev,
        args,
        stubs: [tx, nonzeroReceipt],
        valid: false,
      },
      {
        name: "should fail if previous has a higher txCountGlobal",
        prev: { ...prev, txCountGlobal: 5000 },
        args,
        stubs: [tx, emptyReceipt],
        valid: false,
      },
    ]

    emptyChannelCases.forEach(async ({ name, prev, args, stubs, valid }) => {
      it(name, async () => {
        // set tx receipt stub
        validator.web3.eth.getTransaction = sinon.stub().returns(stubs[0])
        validator.web3.eth.getTransactionReceipt = sinon.stub().returns(stubs[1])
        if (valid) {
          assert.isNull(await validator.emptyChannel(prev, args))
        } else {
          assert.exists(await validator.emptyChannel(prev, args))
        }
      })
    })
  })

  describe.skip('openThread', () => {

    const params = createChannelThreadOverrides(2, { threadId: 70, receiver: t.mkAddress() })
    // contains 2 threads, one where user is sender
    // one where user is receiver
    const initialThreadStates = params.initialThreadStates
    const { threadRoot, threadCount, ...res } = params

    const prev = createPreviousChannelState({
      threadCount,
      threadRoot,
      balanceToken: [10, 10],
      balanceWei: [10, 10]
    })

    const args = createThreadState()

    const cases = [
      {
        name: 'should work with first thread',
        prev: { ...prev, threadRoot: EMPTY_ROOT_HASH, threadCount: 0 },
        initialThreadStates: [],
        sigErr: false,
        args,
        valid: true,
      },
      {
        name: 'should work for additional threads',
        prev,
        initialThreadStates,
        sigErr: false,
        args,
        valid: true,
      },
      {
        name: 'should return a string if an incorrect signer is detected',
        prev,
        initialThreadStates,
        sigErr: true,
        args,
        valid: false,
      },
      {
        name: 'should return a string if the tx count is non-zero',
        prev,
        initialThreadStates,
        sigErr: false,
        args: { ...args, txCount: 7 },
        valid: false,
      },
      {
        name: 'should return a string if the contract address is not the same as channel',
        prev,
        initialThreadStates,
        sigErr: false,
        args: { ...args, contractAddress: t.mkAddress('0xFFF') },
        valid: false,
      },
      {
        name: 'should return a string if the receiver wei balance is non-zero',
        prev,
        initialThreadStates,
        sigErr: false,
        args: { ...args, balanceWeiReceiver: toBN(2) },
        valid: false,
      },
      {
        name: 'should return a string if the receiver token balance is non-zero',
        prev,
        initialThreadStates,
        sigErr: false,
        args: { ...args, balanceTokenReceiver: toBN(2) },
        valid: false,
      },
      {
        name: 'should return a string if the thread sender (as hub) cannot afford to create the thread',
        prev,
        initialThreadStates,
        sigErr: false,
        args: { ...args, balanceWeiSender: toBN(20), balanceTokenSender: toBN(20), receiver: prev.user, sender: t.mkAddress('0xAAA') },
        valid: false,
      },
      {
        name: 'should return a string if the thread sender (as user) cannot afford to create the thread',
        prev,
        initialThreadStates,
        sigErr: false,
        args: { ...args, balanceWeiSender: toBN(20), balanceTokenSender: toBN(20) },
        valid: false,
      },
    ]

    cases.forEach(async ({ name, prev, initialThreadStates, sigErr, args, valid }) => {
      it(name, async () => {
        // ignore recovery by defaul
        validator.assertThreadSigner = sinon.stub().returns(null)
        if (sigErr)
          validator.assertThreadSigner = sinon.stub().throws(new Error(`Incorrect signer`))

        if (valid) {
          assert.isNull(await validator.openThread(prev, initialThreadStates, args))
        } else {
          assert.exists(await validator.openThread(prev, initialThreadStates, args))
        }

      })
    })
  })

  describe.skip('closeThread', () => {
    const params = createChannelThreadOverrides(2, { sender: t.mkAddress('0x18'), receiver: sampleAddr })
    // contains 2 threads, one where user is sender
    // one where user is receiver
    const initialThreadStates = params.initialThreadStates
    const { threadRoot, threadCount, ...res } = params

    const prev = createPreviousChannelState({
      threadCount,
      threadRoot,
      balanceToken: [10, 10],
      balanceWei: [10, 10]
    })

    const args = createThreadState({
      ...initialThreadStates[0], // user is receiver
      balanceWei: [3, 2],
      balanceToken: [2, 3]
    })

    const cases = [
      {
        name: 'should work',
        prev,
        initialThreadStates,
        args,
        sigErr: false, // stubs out sig recover in tests
        valid: true,
      },
      {
        name: 'should return a string if the args provided is not included in initial states',
        prev,
        initialThreadStates: [initialThreadStates[1]],
        args,
        sigErr: false,
        valid: false,
      },
      {
        name: 'should return a string if the signer did not sign args',
        prev,
        initialThreadStates,
        args,
        sigErr: true, // stubs out sig recover in tests
        valid: false,
      },
      {
        name: 'should return a string if the final state wei balance is not conserved',
        prev,
        initialThreadStates,
        args: { ...args, balanceWeiSender: toBN(10) },
        sigErr: false, // stubs out sig recover in tests
        valid: false,
      },
      {
        name: 'should return a string if the final state token balance is not conserved',
        prev,
        initialThreadStates,
        args: { ...args, balanceTokenSender: toBN(10), balanceWeiSender: toBN(10) },
        sigErr: false, // stubs out sig recover in tests
        valid: false,
      },
    ]
    cases.forEach(async ({ name, prev, initialThreadStates, sigErr, args, valid }) => {
      it(name, async () => {
        // ignore recovery by defaul
        validator.assertThreadSigner = sinon.stub().returns(null)
        if (sigErr)
          validator.assertThreadSigner = sinon.stub().throws(new Error(`Incorrect signer`))

        if (valid) {
          assert.isNull(await validator.closeThread(prev, initialThreadStates, args))
        } else {
          assert.exists(await validator.closeThread(prev, initialThreadStates, args))
        }

      })
    })
  })

  function getProposePendingCases() {
    const prev = createPreviousChannelState({
      balanceToken: [5, 5],
      balanceWei: [5, 5],
    })
    const args = createProposePendingArgs()

    return [
      {
        name: 'should work',
        prev,
        args,
        valid: true,
      },
      {
        name: 'should return a string if args are negative',
        prev,
        args: createProposePendingArgs({
          depositWeiUser: -1,
        }),
        valid: false,
      },
      {
        name: 'should error if withdrawal exceeds balance',
        prev,
        args: createProposePendingArgs({
          withdrawalWeiUser: 100,
        }),
        valid: false,
      },
      {
        name: 'should error if timeout is negative',
        prev,
        args: createProposePendingArgs({
          timeout: -1,
        }),
        valid: false,
      },
    ]
  }

  describe('proposePending', () => {
    getProposePendingCases().forEach(async ({ name, prev, args, valid }) => {
      it(name, async () => {
        if (valid) {
          assert.isNull(await validator.proposePending(prev, args))
        } else {
          assert.exists(await validator.proposePending(prev, args))
        }
      })
    })
  })

  describe('proposePendingExchange', () => {
    const prev = createPreviousChannelState({
      balanceToken: [5, 5],
      balanceWei: [5, 5],
    })
    const args: PendingExchangeArgsBN = {
      exchangeRate: '2',
      weiToSell: toBN(0),
      tokensToSell: toBN(0),
      seller: "user",
      ...createProposePendingArgs(),
    }

    function runCase(tc: { name: string, prev: ChannelStateBN, args: PendingExchangeArgsBN, valid: boolean }) {
      it(tc.name, async () => {
        if (tc.valid) {
          assert.isNull(await validator.proposePendingExchange(tc.prev, tc.args))
        } else {
          assert.exists(await validator.proposePendingExchange(tc.prev, tc.args))
        }
      })
    }

    const proposePendingExchangeCases = [
      {
        name: 'exchange + withdrawal makes balance 0',
        prev,
        args: {
          ...args,
          tokensToSell: toBN(2),
          withdrawalTokenUser: toBN(3),
        },
        valid: true,
      },

      {
        name: 'exchange + withdrawal makes balance negative',
        prev,
        args: {
          ...args,
          tokensToSell: toBN(4),
          withdrawalTokenUser: toBN(4),
        },
        valid: false,
      },

      {
        name: 'hub withdraws sold tokens',
        prev,
        args: {
          ...args,
          tokensToSell: toBN(5),
          withdrawalTokenHub: toBN(7),
        },
        valid: true,
      },

      {
        name: 'user withdraws purchased wei',
        prev,
        args: {
          ...args,
          tokensToSell: toBN(4),
          withdrawalWeiUser: toBN(7),
        },
        valid: true,
      },

    ]

    proposePendingExchangeCases.forEach(runCase)

    describe('with pending cases', () => {
      getProposePendingCases().forEach(tc => {
        runCase({ ...tc, args: { ...args, weiToSell: toBN(1), ...tc.args } })
      })
    })

    describe('with exchange cases', () => {
      getExchangeCases().forEach(tc => {
        runCase({ ...tc, args: { ...args, ...tc.args as ExchangeArgsBN } })
      })
    })
  })

  describe.skip('threadPayment', () => {
    const prev = createThreadState()
    const args = createThreadPaymentArgs()

    const threadPaymentCases = [
      {
        name: 'should work',
        args,
        valid: true,
      },
      {
        name: 'should return a string if payment args are negative',
        args: createThreadPaymentArgs({
          amountToken: -1,
          amountWei: -1,
        }),
        valid: false,
      },
      {
        name: 'should return a string if payment exceeds available thread balance',
        args: createThreadPaymentArgs({
          amountToken: 20,
          amountWei: 20,
        }),
        valid: false,
      },
    ]

    threadPaymentCases.forEach(async ({ name, args, valid }) => {
      it(name, async () => {
        if (valid) {
          assert.isNull(await validator.threadPayment(prev, args))
        } else {
          assert.exists(await validator.threadPayment(prev, args))
        }
      })
    })
  })
})


/* EG of tx receipt obj string, use JSON.parse
const txReceipt = {
  "transactionHash": "${t.mkHash('0xhash')}",
  "transactionIndex": 0,
  "blockHash": "0xe352de5c890efc61876e239e15ed474f93604fdbc5f542ff28c165c25b0b6d55", "blockNumber": 437,
  "gasUsed": 609307,
  "cumulativeGasUsed": 609307,
  "contractAddress": "${t.mkAddress('0xCCC')}",
  "logs":
    [{
      "logIndex": 0,
      "transactionIndex": 0,
      "transactionHash": "0xae51947afec970dd134ce1d8589c924b99bfa6a3b7f2d61cb95a447804a196a7",
      "blockHash": "${t.mkHash('0xblock')}",
      "blockNumber": 437,
      "address": "0x9378e143606A4666AD5F20Ac8865B44e703e321e",
      "data": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x0000000000000000000000002da565caa7037eb198393181089e92181ef5fb53", "0x0000000000000000000000003638eeb7733ed1fb83cf028200dfb2c41a6d9da8"],
      "type": "mined",
      "id": "log_9f6b5361"
    },
    {
      "logIndex": 1,
      "transactionIndex": 0,
      "transactionHash": "0xae51947afec970dd134ce1d8589c924b99bfa6a3b7f2d61cb95a447804a196a7",
      "blockHash": "0xe352de5c890efc61876e239e15ed474f93604fdbc5f542ff28c165c25b0b6d55",
      "blockNumber": 437,
      "address": "0x9378e143606A4666AD5F20Ac8865B44e703e321e",
      "data": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x0000000000000000000000003638eeb7733ed1fb83cf028200dfb2c41a6d9da8", "0x0000000000000000000000002da565caa7037eb198393181089e92181ef5fb53"],
      "type": "mined",
      "id": "log_18b4ce0a"
    },
    {
      "logIndex": 2,
      "transactionIndex": 0,
      "transactionHash": "0xae51947afec970dd134ce1d8589c924b99bfa6a3b7f2d61cb95a447804a196a7",
      "blockHash": "0xe352de5c890efc61876e239e15ed474f93604fdbc5f542ff28c165c25b0b6d55",
      "blockNumber": 437,
      "address": "0x3638EEB7733ed1Fb83Cf028200dfb2C41A6D9DA8",
      "data": "0x00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "topics": ["0xeace9ecdebd30bbfc243bdc30bfa016abfa8f627654b4989da4620271dc77b1c", "0x0000000000000000000000002da565caa7037eb198393181089e92181ef5fb53"],
      "type": "mined",
      "id": "log_bc5572a6"
    }],
  "status": true,
  "logsBloom": "0x00000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000020000000000000000000020000000000000000000008000000000000000000040000000000000008000000420000000000000000000000000000080000000000000000000810000000000000000000000000000000000000000000020000000000000000000000000000000100000000000000000000000000000000000000000000000000040000000000000002000008000000000000000000000000000000000000000000000000000000008000000000000000000000000000001000000000000000000000000000"
}
*/
