import {
  Registry,
  PartialServiceDefinitions,
  Context,
  Container,
} from './Container'
import { ChannelManager } from './ChannelManager'
import AuthApiService from './api/AuthApiService'
import { MemoryCRAuthManager } from './CRAuthManager'
import Config from './Config'
import BrandingApiService from './api/BrandingApiService'
import {
  default as DBEngine,
  PostgresDBEngine,
  PgPoolService,
} from './DBEngine'
import PaymentsApiService from './api/PaymentsApiService'
import ExchangeRateService from './ExchangeRateService'
import ExchangeRateDao, { PostgresExchangeRateDao } from './dao/ExchangeRateDao'
import { Client } from 'pg'
import PaymentsDao, { PostgresPaymentsDao } from './dao/PaymentsDao'
import { PostgresWithdrawalsDao } from './dao/WithdrawalsDao'
import GlobalSettingsDao, {
  PostgresGlobalSettingsDao
} from './dao/GlobalSettingsDao'
//import GlobalSettingsApiService from './api/GlobalSettingsApiService'
import ExchangeRateApiService from './api/ExchangeRateApiService'
import { default as ChannelsDao, PostgresChannelsDao } from './dao/ChannelsDao'
import { PaymentMetaDao, PostgresPaymentMetaDao } from './dao/PaymentMetaDao'
import { default as ChainsawDao, PostgresChainsawDao } from './dao/ChainsawDao'
import ChannelsService from './ChannelsService'
import ThreadsDao, { PostgresThreadsDao } from './dao/ThreadsDao'
import ChannelsApiService from './api/ChannelsApiService'
import ChainsawService from './ChainsawService'

import {
  PostgresDisbursementDao,
} from './dao/DisbursementsDao'
import { getRedisClient, RedisClient } from './RedisClient'
import {
  default as GasEstimateDao,
  PostgresGasEstimateDao,
} from './dao/GasEstimateDao'
import { default as GasEstimateService } from './GasEstimateService'
import { default as GasEstimateApiService } from './api/GasEstimateApiService'
import Web3 from 'web3'
import { PostgresFeatureFlagsDao } from './dao/FeatureFlagsDao'
import FeatureFlagsApiService from './api/FeatureFlagsApiService'
import { ApiServer } from './ApiServer'
import { DefaultAuthHandler } from './middleware/AuthHandler'
import { Utils } from './vendor/connext/Utils'
import { Validator } from './vendor/connext/validator'
import ThreadsService from './ThreadsService'
import ThreadsApiService from './api/ThreadsApiService';
import { OnchainTransactionService } from "./OnchainTransactionService";
import { OnchainTransactionsDao } from "./dao/OnchainTransactionsDao";
import { StateGenerator } from './vendor/connext/StateGenerator';
import { SignerService } from './SignerService';
import PaymentsService from './PaymentsService';
import { default as ChannelManagerABI } from './abi/ChannelManager'
import { CloseChannelService } from './CloseChannelService'
import ChannelDisputesDao, { PostgresChannelDisputesDao } from './dao/ChannelDisputesDao';

export default function defaultRegistry(otherRegistry?: Registry): Registry {
  const registry = new Registry(otherRegistry)
  registry.bindDefinitions(serviceDefinitions)
  return registry
}

export const serviceDefinitions: PartialServiceDefinitions = {
  //
  // Singletons
  //

  PgPoolService: {
    factory: (config: Config) => new PgPoolService(config),
    dependencies: ['Config'],
    isSingleton: true,
  },

  GasEstimateService: {
    factory: (dao: GasEstimateDao) => new GasEstimateService(dao),
    dependencies: ['GasEstimateDao'],
    isSingleton: true,
  },

  ExchangeRateService: {
    factory: (dao: ExchangeRateDao) => new ExchangeRateService(dao),
    dependencies: ['ExchangeRateDao'],
    isSingleton: true,
  },

  ChainsawService: {
    factory: (
      signerService: SignerService,
      chainsawDao: ChainsawDao,
      channelsDao: ChannelsDao,
      channelDisputesDao: ChannelDisputesDao,
      contract: ChannelManager,
      web3: Web3,
      utils: Utils,
      config: Config,
      db: DBEngine,
      validator: Validator,
    ) => new ChainsawService(signerService, chainsawDao, channelsDao, channelDisputesDao, contract, web3, utils, config, db, validator),
    dependencies: [
      'SignerService',
      'ChainsawDao',
      'ChannelsDao',
      'ChannelDisputesDao',
      'ChannelManagerContract',
      'Web3',
      'ConnextUtils',
      'Config',
      'DBEngine',
      'Validator',
    ],
    isSingleton: true,
  },

  CloseChannelService: {
    factory: (
      onchainTxService: OnchainTransactionService,
      signerService: SignerService,
      channelDisputesDao: ChannelDisputesDao,
      channelsDao: ChannelsDao,
      contract: ChannelManager,
      config: Config,
      web3: any,
      db: DBEngine,
    ) => new CloseChannelService(onchainTxService, signerService, channelDisputesDao, channelsDao, contract, config, web3, db),
    dependencies: [
      'OnchainTransactionService',
      'SignerService',
      'ChannelDisputesDao',
      'ChannelsDao',
      'ChannelManagerContract',
      'Config',
      'Web3',
      'DBEngine'
    ],
    isSingleton: true,
  },

  ApiServer: {
    factory: (container: Container) => new ApiServer(container),
    dependencies: ['Container'],
    isSingleton: true,
  },

  ApiServerServices: {
    factory: () => [
      GasEstimateApiService,
      FeatureFlagsApiService,
      ChannelsApiService,
      BrandingApiService,
      AuthApiService,
      ExchangeRateApiService,
      ThreadsApiService,
      PaymentsApiService,
    ],
    isSingleton: true,
  },

  OnchainTransactionService: {
    factory: (
      web3: any,
      gasEstimateDao: GasEstimateDao,
      onchainTransactionDao: OnchainTransactionsDao,
      db: DBEngine,
      container: Container,
    ) => new OnchainTransactionService(web3, gasEstimateDao, onchainTransactionDao, db, container),
    dependencies: [
      'Web3',
      'GasEstimateDao',
      'OnchainTransactionsDao',
      'DBEngine',
      'Container',
    ],
    isSingleton: true,
  },

  CRAuthManager: {
    factory: (web3: any) => new MemoryCRAuthManager(web3),
    dependencies: ['Web3'],
    isSingleton: true,
  },

  ChannelManagerContract: {
    factory: (
      web3: any,
      config: Config,
    ) => new web3.eth.Contract(
      ChannelManagerABI.abi,
      config.channelManagerAddress,
    ) as ChannelManager,
    dependencies: [
      'Web3',
      'Config',
    ],
    isSingleton: true,
  },

  //
  // Factories
  //

  OnchainTransactionsDao: {
    factory: () => new OnchainTransactionsDao(),
  },

  PaymentMetaDao: {
    factory: (db: DBEngine<Client>, config: Config) => new PostgresPaymentMetaDao(db, config),
    dependencies: ['DBEngine', 'Config'],
  },

  ExchangeRateDao: {
    factory: (db: DBEngine<Client>) => new PostgresExchangeRateDao(db),
    dependencies: ['DBEngine'],
  },

  GlobalSettingsDao: {
    factory: (db: DBEngine<Client>) => new PostgresGlobalSettingsDao(db),
    dependencies: ['DBEngine'],
    isSingleton: true
  },

  ChainsawDao: {
    factory: (db: DBEngine<Client>, config: Config) =>
      new PostgresChainsawDao(db, config),
    dependencies: ['DBEngine', 'Config'],
  },

  PaymentsDao: {
    factory: (db: DBEngine<Client>) =>
      new PostgresPaymentsDao(db),
    dependencies: ['DBEngine'],
  },

  WithdrawalsDao: {
    factory: (db: DBEngine<Client>) => new PostgresWithdrawalsDao(db),
    dependencies: ['DBEngine'],
  },

  DBEngine: {
    factory: (pool: PgPoolService, context: Context) =>
      new PostgresDBEngine(pool, context),
    dependencies: ['PgPoolService', 'Context'],
  },

  DisbursementDao: {
    factory: (db: DBEngine<Client>) => new PostgresDisbursementDao(db),
    dependencies: ['DBEngine'],
  },

  ConnextUtils: {
    factory: () => new Utils(),
    dependencies: [],
  },

  Validator: {
    factory: (web3: any, config: Config) => new Validator(web3, config.hotWalletAddress),
    dependencies: ['Web3', 'Config'],
  },

  StateGenerator: {
    factory: () => new StateGenerator(),
    dependencies: [],
  },

  GasEstimateDao: {
    factory: (db: DBEngine<Client>, redis: RedisClient) =>
      new PostgresGasEstimateDao(db, redis),
    dependencies: ['DBEngine', 'RedisClient'],
  },

  RedisClient: {
    factory: (config: Config) => getRedisClient(config.redisUrl),
    dependencies: ['Config'],
    isSingleton: true
  },

  FeatureFlagsDao: {
    factory: (client: DBEngine<Client>) => new PostgresFeatureFlagsDao(client),
    dependencies: ['DBEngine'],
  },

  AuthHandler: {
    factory: (config: Config) => new DefaultAuthHandler(config),
    dependencies: ['Config'],
  },

  Context: {
    factory: () => {
      throw new Error(
        'A Context instance should be provided by the instanciator ' +
        '(see comments on the Context class)'
      )
    }
  },

  ChannelsDao: {
    factory: (db: DBEngine<Client>, config: Config) =>
      new PostgresChannelsDao(db, config),
    dependencies: ['DBEngine', 'Config'],
  },

  ThreadsDao: {
    factory: (db: DBEngine<Client>, config: Config) =>
      new PostgresThreadsDao(db, config),
    dependencies: ['DBEngine', 'Config'],
  },

  ChannelDisputesDao: {
    factory: (db: DBEngine<Client>, config: Config) =>
      new PostgresChannelDisputesDao(db, config),
    dependencies: ['DBEngine', 'Config'],
  },

  SignerService: {
    factory: (web3: any, contract: ChannelManager, utils: Utils, config: Config) => new SignerService(web3, contract, utils, config),
    dependencies: ['Web3', 'ChannelManagerContract', 'ConnextUtils', 'Config']
  },

  PaymentsService: {
    factory: (
      channelsService: ChannelsService,
      threadsService: ThreadsService,
      signerService: SignerService,
      paymentsDao: PaymentsDao,
      paymentMetaDao: PaymentMetaDao,
      channelsDao: ChannelsDao,
      validator: Validator,
      config: Config,
      db: DBEngine,
      contract: ChannelManager,
    ) => new PaymentsService(
      channelsService,
      threadsService,
      signerService,
      paymentsDao,
      paymentMetaDao,
      channelsDao,
      validator,
      config,
      db,
    ),
    dependencies: [
      'ChannelsService',
      'ThreadsService',
      'SignerService',
      'PaymentsDao',
      'PaymentMetaDao',
      'ChannelsDao',
      'Validator',
      'Config',
      'DBEngine',
      'ChannelManagerContract',
    ],
  },

  ChannelsService: {
    factory: (
      onchainTx: OnchainTransactionService,
      threadsService: ThreadsService,
      signerService: SignerService,
      channelsDao: ChannelsDao,
      threadsDao: ThreadsDao,
      exchangeRateDao: ExchangeRateDao,
      channelDisputesDao: ChannelDisputesDao,
      generator: StateGenerator,
      validation: Validator,
      redis: RedisClient,
      db: DBEngine,
      config: Config,
      contract: ChannelManager,
    ) =>
      new ChannelsService(
        onchainTx,
        threadsService,
        signerService,
        channelsDao,
        threadsDao,
        exchangeRateDao,
        channelDisputesDao,
        generator,
        validation,
        redis,
        db,
        config,
        contract,
      ),
    dependencies: [
      'OnchainTransactionService',
      'ThreadsService',
      'SignerService',
      'ChannelsDao',
      'ThreadsDao',
      'ExchangeRateDao',
      'ChannelDisputesDao',
      'StateGenerator',
      'Validator',
      'RedisClient',
      'DBEngine',
      'Config',
      'ChannelManagerContract',
    ],
  },

  ThreadsService: {
    factory: (
      signerService: SignerService,
      channelsDao: ChannelsDao,
      threadsDao: ThreadsDao,
      validation: Validator,
      config: Config,
      gsd: GlobalSettingsDao
    ) => new ThreadsService(signerService, channelsDao, threadsDao, validation, config, gsd),
    dependencies: [
      'SignerService',
      'ChannelsDao',
      'ThreadsDao',
      'Validator',
      'Config',
      'GlobalSettingsDao'
    ],
  },
}
