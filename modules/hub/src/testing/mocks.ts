import * as request from 'supertest'

import { getRedisClient } from '../RedisClient'
import { PgPoolService } from '../DBEngine'
import { Container } from '../Container'

import { truncateAllTables } from './eraseDb'
import { ApiServer } from '../ApiServer'
import { Role } from "../Role";
import { mkAddress, mkSig, mkHash } from "./stateUtils";
import { Validator } from '../vendor/connext/validator'
import { Big } from '../util/bigNumber';
import { SignerService } from '../SignerService';
import { Utils } from '../vendor/connext/Utils';
import Config from '../Config';
import { ChannelManagerChannelDetails } from '../vendor/connext/types';

const Web3 = require('web3')

let pgIsDirty = true

export class PgPoolServiceForTest extends PgPoolService {
  testNeedsReset = true

  constructor(config: any) {
    super(config)

    this.pool.on('connect', client => {
      pgIsDirty = true
    })

    before(() => this.clearDatabase())
  }

  async clearDatabase() {
    if (!pgIsDirty)
      return

    const cxn = await this.pool.connect()
    try {
      if (this.testNeedsReset) {
        await truncateAllTables(cxn as any)
      }
    } finally {
      cxn.release()
    }
    pgIsDirty = false
  }
}

export class TestApiServer extends ApiServer {
  request: request.SuperTest<request.Test>

  constructor(container: Container) {
    super(container)
    this.request = request(this.app)
  }

  withUser(address?: string): TestApiServer {
    address = address || '0xfeedface'
    return this.container.resolve('TestApiServer', {
      'AuthHandler': {
        rolesFor: (req: any) => {
          req.session.address = address
          return [Role.AUTHENTICATED]
        },
        isAuthorized: () => true,
      },
    })
  }
}

// NOTE: This is a work in progress
class MockWeb3Provider {
  countId = 1

  _getResponse(result) {
    return {
      jsonrpc: '2.0',
      id: this.countId,
      result,
    }
  }

  _getError(msg) {
    return {
      jsonrpc: '2.0',
      id: this.countId,
      error: {
        code: 1234,
        message: msg,
      }
    }
  }

  send(payload) {
    throw new Error('sync send not supported')
  }

  sendAsync(payload, callback) {
    if (payload.id)
      this.countId = payload.id

    console.log('SEND ASYNC:', payload)
  }

  on(type, callback) {
    throw new Error('uh oh: ' + type)
  }
}

class MockValidator extends Validator {
  constructor() {
    super({} as any, '0xfoobar')
  }

  assertChannelSigner() {
    return null
  }

  assertThreadSigner() {
    return null
  }

  assertDepositRequestSigner(req: any) {
    if (!req.sigUser) {
      throw new Error('No signature detected')
    }
    return null
  }
}

export const getTestConfig = (overrides?: any) => ({
  ...Config.fromEnv(),
  databaseUrl: process.env.DATABASE_URL_TEST!,
  redisUrl: 'redis://localhost:6379/6',
  sessionSecret: 'hummus',
  hotWalletAddress: '0x7776900000000000000000000000000000000000',
  channelManagerAddress: mkAddress('0xCCC'),
  ...(overrides || {}),
})

export class MockGasEstimateDao {
  async latest() {
    return {
      retrievedAt: Date.now(),
      speed: 1,
      blockNum: 1,
      blockTime: 15,

      fastest: 9,
      fastestWait: 9.9,

      fast: 6,
      fastWait: 6.6,

      average: 4,
      avgWait: 4.4,

      safeLow: 2,
      safeLowWait: 2.2,
    }
  }
}

export const mockRate = Big(123.45)
export class MockExchangeRateDao {
  async latest() {
    return {
      retrievedAt: Date.now(),
      rates: {
        USD: mockRate
      }
    }
  }
}

export const fakeSig = mkSig('0xabc123')
export class MockSignerService extends SignerService {
  constructor() {
    super({
      eth: {
        getBlock: async (block: string | number) => {
          if (block === 'latest') {
            return { timestamp: Math.floor(Date.now() / 1000) }
          }
        },
        sign: async () => {
          return
        },
        getTransactionCount: async () => {
          return 1
        },
        estimateGas: async () => {
          return 1000
        },
        signTransaction: async () => {
          return {
            tx: {
              hash: mkHash('0xaaa'),
              r: mkHash('0xabc'),
              s: mkHash('0xdef'),
              v: '0x27',
            },
          }
        },
        sendSignedTransaction: () => {
          console.log(`Called mocked web3 function sendSignedTransaction`)
          return {
            on: (input, cb) => {
              switch (input) {
                case 'transactionHash':
                  return cb(mkHash('0xbeef'))
                case 'error':
                  return cb(null)
              }
            },
          }
        },
        sendTransaction: () => {
          console.log(`Called mocked web3 function sendTransaction`)
          return {
            on: (input, cb) => {
              switch (input) {
                case 'transactionHash':
                  return cb(mkHash('0xbeef'))
                case 'error':
                  return cb(null)
              }
            },
          }
        },
      },
    }, {} as any, new Utils(), getTestConfig())
  }
  async getSigForChannelState() {
    return fakeSig
  }
  async getChannelDetails() {
    return {
      channelClosingTime: fakeClosingTime,
      exitInitiator: '',
      status: '',
      threadCount: 0,
      threadRoot: '',
      txCountChain: 1,
      txCountGlobal: 1
    } as ChannelManagerChannelDetails
  }
}

export let fakeClosingTime: number = 0
export function setFakeClosingTime(time: number) {
  fakeClosingTime = time
}
export function clearFakeClosingTime() {
  fakeClosingTime = 0
}

export class MockChannelManagerContract {
  methods = {
    hubAuthorizedUpdate: () => {
      return {
        send: async () => {
          console.log(`Called mocked contract function hubAuthorizedUpdate`)
          return true
        },
        encodeABI: () => {
          console.log(`Called mocked contract function hubAuthorizedUpdate`)
          return true
        },
      }
    },
    getChannelDetails: () => {
      console.log(`Called mocked contract function getChannelDetails`)
      return {
        call: async () => {
          return [
            1, // txCountGlobal
            1, // txCountChain
            '', // threadRoot 
            0, // threadCount
            '', // exitInitiator 
            fakeClosingTime, // channelClosingTime
            '' // status
          ]
        }
      }
    },
    startExitWithUpdate: () => {
      console.log(`Called mocked contract function startExitWithUpdate`)
      return {
        send: async () => {
          return true
        },
        encodeABI: () => {
          return '0xdeadbeef'
        },
      }
    },
    startExit: () => {
      console.log(`Called mocked contract function startExit`)
      return {
        send: async () => {
          return true
        },
        encodeABI: () => {
          return '0xdeadbeef'
        },
      }
    },
    challengePeriod: () => {
      return {
        call: async () => {
          return 0
        }
      }
    }
  }
}

export const mockServices: any = {
  'Config': {
    factory: getTestConfig,
  },

  'RedisClient': {
    factory: (config: any) => {
      const client = getRedisClient(config.redisUrl)
      client.flushall()
      return client
    },
    dependencies: ['Config'],
    isSingleton: true
  },

  'PgPoolService': {
    factory: (config: any) => new PgPoolServiceForTest(config),
    dependencies: ['Config'],
  },

  'TestApiServer': {
    factory: (container: Container) => new TestApiServer(container),
    dependencies: ['Container'],
  },

  'Web3': {
    // TODO: Finish this: new Web3(new Web3.providers.HttpProvider('http://127.0.0.1:8545'))
    factory: () => new Web3(new Web3.providers.HttpProvider('http://127.0.0.1:8545')),
    dependencies: []
  },

  'Validator': {
    factory: () => new MockValidator(),
  },

  'ExchangeRateDao': {
    factory: () => new MockExchangeRateDao(),
  },

  'SignerService': {
    factory: () => new MockSignerService(),
  },

  'ChannelManagerContract': {
    factory: () => new MockChannelManagerContract(),
  },
}
