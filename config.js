module.exports = {
  // Node configuration
  nodeNum: 64,
  byzantineNodeNum: 16,

  // Protocol parameters
  lambda: 1,
  protocol: 'async-BA',

  // Network conditions
  networkDelay: {
    mean: 1.0,
    std: 0.5,
  },

  // Attacker configuration
  attacker: 'sync-interfernce-attacker',

  // Other parameters
  logToFile: true,
  repeatTime: 50,

  // Additional Babble specific configuration
  babble: {
    suspendLimit: 200,
    syncInterval: 500,
  }
};
