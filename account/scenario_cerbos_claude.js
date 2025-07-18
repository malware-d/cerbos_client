const jwt = require('jsonwebtoken');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

// JWT Secret (same as in index.js)
const JWT_SECRET = 'd1f8a9b3c5e7f2a4d6c8b0e5f3a7d2c1b5e8f3a6d9c2b7e4f1a8d3c6b9e5f2a1';
const WRONG_JWT_SECRET = 'wrong-secret-key-for-mitm-attack';

// Base URL for the API
const BASE_URL = 'http://localhost:3000';

// Log file setup
const LOG_DIR = path.join(__dirname, 'logs');
const LOG_FILE = path.join(LOG_DIR, 'cerbos_test.log');

// Tạo thư mục logs nếu chưa tồn tại
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}
const logStream = fs.createWriteStream(LOG_FILE, { flags: 'w' });

// Xử lý lỗi khi ghi log
logStream.on('error', (error) => {
  console.error(`Error writing to log file ${LOG_FILE}: ${error.message}`);
});

// Test users with different roles
const TEST_USERS = {
  client: {
    sub: 'mb000001',
    name: 'Nguyen Van Anh',
    roles: ['client'],
    account_id: 'acc001',
    account_type: 'normal'
  },
  vip_client: {
    sub: 'mb000002', 
    name: 'Dao Van Binh',
    roles: ['vip_client'],
    account_id: 'acc002',
    account_type: 'vip'
  },
  teller: {
    sub: 'teller001',
    name: 'Teller User',
    roles: ['teller'],
    account_id: 'acc001',
    account_type: 'normal'
  },
  supervisor: {
    sub: 'supervisor001',
    name: 'Supervisor User', 
    roles: ['supervisor'],
    account_id: 'acc001',
    account_type: 'normal'
  },
  admin: {
    sub: 'admin001',
    name: 'Admin User',
    roles: ['admin'],
    account_id: 'acc001',
    account_type: 'normal'
  }
};

// Generate JWT token for a user
function generateToken(user, options = {}) {
  const { secret = JWT_SECRET, expiresIn } = options;
  const signOptions = { algorithm: 'HS256' };
  if (expiresIn) {
    signOptions.expiresIn = expiresIn;
  }
  return jwt.sign(user, secret, signOptions);
}

// Color codes for console output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m'
};

// Enhanced logging function that writes to both console and file
function log(message, color = colors.white) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${message.replace(/\x1b\[\d+m/g, '')}`;
  
  // Write to file (strip color codes)
  try {
    logStream.write(logMessage + '\n', (error) => {
      if (error) {
        console.error(`Error writing log to file: ${error.message}`);
      }
    });
  } catch (error) {
    console.error(`Error writing log to file: ${error.message}`);
  }
  
  // Write to console with colors
  console.log(`${color}${message}${colors.reset}`);
}

function logSuccess(message) {
  log(`✅ ${message}`, colors.green);
}

function logError(message) {
  log(`❌ ${message}`, colors.red);
}

function logInfo(message) {
  log(`ℹ️  ${message}`, colors.blue);
}

function logWarning(message) {
  log(`⚠️  ${message}`, colors.yellow);
}

function logHeader(message) {
  log(`\n${colors.bright}${'='.repeat(60)}${colors.reset}`);
  log(`${colors.bright}${message}${colors.reset}`);
  log(`${colors.bright}${'='.repeat(60)}${colors.reset}`);
}

function logSubHeader(message) {
  log(`\n${colors.cyan}--- ${message} ---${colors.reset}`);
}

// Test scenarios based on account.yaml policy
const TEST_SCENARIOS = [
  // READ action tests
  {
    name: 'READ Account - Client Role',
    method: 'GET',
    endpoint: '/accounts/acc001',
    user: 'client',
    expectedStatus: 200,
    description: 'Client should be able to read account (allowed for client, teller, supervisor, admin)'
  },
  {
    name: 'READ Account - Teller Role',
    method: 'GET', 
    endpoint: '/accounts/acc001',
    user: 'teller',
    expectedStatus: 200,
    description: 'Teller should be able to read account'
  },
  {
    name: 'READ Account - Supervisor Role',
    method: 'GET',
    endpoint: '/accounts/acc001', 
    user: 'supervisor',
    expectedStatus: 200,
    description: 'Supervisor should be able to read account'
  },
  {
    name: 'READ Account - Admin Role',
    method: 'GET',
    endpoint: '/accounts/acc001',
    user: 'admin',
    expectedStatus: 200,
    description: 'Admin should be able to read account'
  },

  // UPDATE action tests (only teller, admin allowed)
  {
    name: 'UPDATE Account - Client Role (Should Fail)',
    method: 'PATCH',
    endpoint: '/accounts/acc001',
    user: 'client',
    expectedStatus: 403,
    description: 'Client should NOT be able to update account (only teller, admin allowed)'
  },
  {
    name: 'UPDATE Account - Teller Role',
    method: 'PATCH',
    endpoint: '/accounts/acc001',
    user: 'teller',
    expectedStatus: 200,
    description: 'Teller should be able to update account'
  },
  {
    name: 'UPDATE Account - Admin Role',
    method: 'PATCH',
    endpoint: '/accounts/acc001',
    user: 'admin',
    expectedStatus: 200,
    description: 'Admin should be able to update account'
  },

  // CREATE action tests (only admin allowed)
  {
    name: 'CREATE Account - Client Role (Should Fail)',
    method: 'POST',
    endpoint: '/accounts/new',
    user: 'client',
    expectedStatus: 403,
    description: 'Client should NOT be able to create account (only admin allowed)'
  },
  {
    name: 'CREATE Account - Teller Role (Should Fail)',
    method: 'POST',
    endpoint: '/accounts/new',
    user: 'teller',
    expectedStatus: 403,
    description: 'Teller should NOT be able to create account (only admin allowed)'
  },
  {
    name: 'CREATE Account - Admin Role',
    method: 'POST',
    endpoint: '/accounts/new',
    user: 'admin',
    expectedStatus: 200,
    description: 'Admin should be able to create account'
  },

  // TRANSFER action tests
  {
    name: 'TRANSFER - Client with Small Amount (≤ 100M)',
    method: 'POST',
    endpoint: '/accounts/acc001/transfer',
    user: 'client',
    data: { amount: 50000000 }, // 50M VND
    expectedStatus: 200,
    description: 'Client should be able to transfer amounts ≤ 100M VND'
  },
  {
    name: 'TRANSFER - Client with Large Amount (> 100M) (Should Fail)',
    method: 'POST',
    endpoint: '/accounts/acc001/transfer',
    user: 'client',
    data: { amount: 150000000 }, // 150M VND
    expectedStatus: 403,
    description: 'Client should NOT be able to transfer amounts > 100M VND'
  },
  {
    name: 'TRANSFER - Client with Exact Limit (100M)',
    method: 'POST',
    endpoint: '/accounts/acc001/transfer',
    user: 'client',
    data: { amount: 100000000 }, // 100M VND exactly
    expectedStatus: 200,
    description: 'Client should be able to transfer exactly 100M VND'
  },
  {
    name: 'TRANSFER - VIP Client with Large Amount',
    method: 'POST',
    endpoint: '/accounts/acc002/transfer',
    user: 'vip_client',
    data: { amount: 1500000000 }, // 1.5B VND
    expectedStatus: 200,
    description: 'VIP Client should be able to transfer any amount'
  },
  {
    name: 'TRANSFER - Teller Role (Should Fail)',
    method: 'POST',
    endpoint: '/accounts/acc001/transfer',
    user: 'teller',
    data: { amount: 50000000 },
    expectedStatus: 403,
    description: 'Teller should NOT be able to transfer (only client roles allowed)'
  },
  {
    name: 'TRANSFER - Admin Role (Should Fail)',
    method: 'POST',
    endpoint: '/accounts/acc001/transfer',
    user: 'admin',
    data: { amount: 50000000 },
    expectedStatus: 403,
    description: 'Admin should NOT be able to transfer (only client roles allowed)'
  },
  // New test cases for JWT validation
  {
    name: 'READ Account - Expired JWT (Should Fail)',
    method: 'GET',
    endpoint: '/accounts/acc001',
    user: 'client',
    tokenOptions: { expiresIn: '-10s' }, // Token expired 10 seconds ago
    expectedStatus: 401,
    description: 'Should fail when using expired JWT token'
  },
  {
    name: 'READ Account - Wrong JWT Secret (MITM) (Should Fail)',
    method: 'GET',
    endpoint: '/accounts/acc001',
    user: 'client',
    tokenOptions: { secret: WRONG_JWT_SECRET }, // Use wrong secret key
    expectedStatus: 401,
    description: 'Should fail when using JWT signed with wrong secret (simulating MITM attack)'
  }
];

// Execute a single test scenario
async function runTestScenario(scenario) {
  logSubHeader(`Testing: ${scenario.name}`);
  logInfo(`Description: ${scenario.description}`);
  
  try {
    const user = TEST_USERS[scenario.user];
    const token = scenario.tokenOptions 
      ? generateToken(user, scenario.tokenOptions)
      : generateToken(user);
    
    logInfo(`User: ${user.name} (${user.roles.join(', ')})`);
    logInfo(`Request: ${scenario.method} ${scenario.endpoint}`);
    
    if (scenario.data) {
      logInfo(`Data: ${JSON.stringify(scenario.data)}`);
    }

    const config = {
      method: scenario.method,
      url: `${BASE_URL}${scenario.endpoint}`,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    };

    if (scenario.data) {
      config.data = scenario.data;
    }

    const response = await axios(config);
    
    if (response.status === scenario.expectedStatus) {
      logSuccess(`PASSED - Status: ${response.status}`);
      logInfo(`Response: ${JSON.stringify(response.data)}`);
      return { passed: true, scenario: scenario.name };
    } else {
      logError(`FAILED - Expected: ${scenario.expectedStatus}, Got: ${response.status}`);
      logInfo(`Response: ${JSON.stringify(response.data)}`);
      return { passed: false, scenario: scenario.name, reason: `Status mismatch: ${response.status} != ${scenario.expectedStatus}` };
    }
    
  } catch (error) {
    const status = error.response?.status || 'NO_RESPONSE';
    const responseData = error.response?.data || error.message;
    
    if (status === scenario.expectedStatus) {
      logSuccess(`PASSED - Status: ${status} (Expected failure)`);
      logInfo(`Response: ${JSON.stringify(responseData)}`);
      if (responseData.details) {
        logInfo(`Error Details: ${responseData.details}`);
      }
      return { passed: true, scenario: scenario.name };
    } else {
      logError(`FAILED - Expected: ${scenario.expectedStatus}, Got: ${status}`);
      logError(`Error: ${JSON.stringify(responseData)}`);
      if (responseData.details) {
        logError(`Error Details: ${responseData.details}`);
      }
      return { passed: false, scenario: scenario.name, reason: `Status mismatch: ${status} != ${scenario.expectedStatus}` };
    }
  }
}

// Run all test scenarios
async function runAllTests() {
  logHeader('CERBOS ACCOUNT POLICY TEST SUITE');
  logInfo('Testing account.yaml policy with all roles and scenarios');
  logInfo(`Server: ${BASE_URL}`);
  
  const results = [];
  
  for (const scenario of TEST_SCENARIOS) {
    const result = await runTestScenario(scenario);
    results.push(result);
    
    // Small delay between tests
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  
  // Summary
  logHeader('TEST RESULTS SUMMARY');
  
  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;
  const total = results.length;
  
  logInfo(`Total Tests: ${total}`);
  logSuccess(`Passed: ${passed}`);
  logError(`Failed: ${failed}`);
  
  if (failed > 0) {
    logSubHeader('Failed Tests:');
    results.filter(r => !r.passed).forEach(r => {
      logError(`- ${r.scenario}: ${r.reason}`);
    });
  }
  
  if (passed === total) {
    logSuccess('\n🎉 ALL TESTS PASSED! Account policy is working correctly.');
  } else {
    logWarning(`\n⚠️  ${failed} test(s) failed. Please check the policy configuration.`);
  }
}

// Run specific test by name
async function runSpecificTest(testName) {
  const scenario = TEST_SCENARIOS.find(s => s.name.toLowerCase().includes(testName.toLowerCase()));
  
  if (!scenario) {
    logError(`Test not found: ${testName}`);
    logInfo('Available tests:');
    TEST_SCENARIOS.forEach(s => logInfo(`- ${s.name}`));
    return;
  }
  
  logHeader(`RUNNING SPECIFIC TEST: ${scenario.name}`);
  await runTestScenario(scenario);
}

// Display available tests
function listTests() {
  logHeader('AVAILABLE TEST SCENARIOS');
  TEST_SCENARIOS.forEach((scenario, index) => {
    log(`${index + 1}. ${scenario.name}`, colors.cyan);
    log(`   ${scenario.description}`, colors.white);
  });
}

// Main function
async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    await runAllTests();
  } else if (args[0] === 'list') {
    listTests();
  } else if (args[0] === 'test') {
    if (args[1]) {
      await runSpecificTest(args[1]);
    } else {
      logError('Please provide a test name');
      logInfo('Usage: node test-tool.js test "test-name"');
    }
  } else {
    logInfo('Usage:');
    logInfo('  node test-tool.js           - Run all tests');
    logInfo('  node test-tool.js list      - List available tests');
    logInfo('  node test-tool.js test "name" - Run specific test');
  }
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  logError(`Uncaught Exception: ${error.message}`);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logError(`Unhandled Rejection at: ${promise}, reason: ${reason}`);
  process.exit(1);
});

// Clean up on exit
process.on('exit', () => {
  logStream.end();
});

// Export for testing
module.exports = {
  runAllTests,
  runSpecificTest,
  listTests,
  TEST_SCENARIOS,
  TEST_USERS
};

// Run if called directly
if (require.main === module) {
  main().catch(error => {
    logError(`Error: ${error.message}`);
    process.exit(1);
  });
}


//tool chay dung, can thì quay lại bản này 
// const jwt = require('jsonwebtoken');
// const axios = require('axios');
// const fs = require('fs');
// const path = require('path');

// // JWT Secret (same as in index.js)
// const JWT_SECRET = 'd1f8a9b3c5e7f2a4d6c8b0e5f3a7d2c1b5e8f3a6d9c2b7e4f1a8d3c6b9e5f2a1';
// const WRONG_JWT_SECRET = 'wrong-secret-key-for-mitm-attack';

// // Base URL for the API
// const BASE_URL = 'http://localhost:3000';

// // Log file setup
// const LOG_FILE = path.join(__dirname, 'cerbos_test.log');
// const logStream = fs.createWriteStream(LOG_FILE, { flags: 'w' });

// // Test users with different roles
// const TEST_USERS = {
//   client: {
//     sub: 'mb000001',
//     name: 'Nguyen Van Anh',
//     roles: ['client'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   },
//   vip_client: {
//     sub: 'mb000002', 
//     name: 'Dao Van Binh',
//     roles: ['vip_client'],
//     account_id: 'acc002',
//     account_type: 'vip'
//   },
//   teller: {
//     sub: 'teller001',
//     name: 'Teller User',
//     roles: ['teller'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   },
//   supervisor: {
//     sub: 'supervisor001',
//     name: 'Supervisor User', 
//     roles: ['supervisor'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   },
//   admin: {
//     sub: 'admin001',
//     name: 'Admin User',
//     roles: ['admin'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   }
// };

// // Generate JWT token for a user
// function generateToken(user, options = {}) {
//   const { secret = JWT_SECRET, expiresIn } = options;
//   const signOptions = { algorithm: 'HS256' };
//   if (expiresIn) {
//     signOptions.expiresIn = expiresIn;
//   }
//   return jwt.sign(user, secret, signOptions);
// }

// // Color codes for console output
// const colors = {
//   reset: '\x1b[0m',
//   bright: '\x1b[1m',
//   red: '\x1b[31m',
//   green: '\x1b[32m',
//   yellow: '\x1b[33m',
//   blue: '\x1b[34m',
//   magenta: '\x1b[35m',
//   cyan: '\x1b[36m',
//   white: '\x1b[37m'
// };

// // Enhanced logging function that writes to both console and file
// function log(message, color = colors.white) {
//   const timestamp = new Date().toISOString();
//   const logMessage = `[${timestamp}] ${message.replace(/\x1b\[\d+m/g, '')}`;
  
//   // Write to file (strip color codes)
//   logStream.write(logMessage + '\n');
  
//   // Write to console with colors
//   console.log(`${color}${message}${colors.reset}`);
// }

// function logSuccess(message) {
//   log(`✅ ${message}`, colors.green);
// }

// function logError(message) {
//   log(`❌ ${message}`, colors.red);
// }

// function logInfo(message) {
//   log(`ℹ️  ${message}`, colors.blue);
// }

// function logWarning(message) {
//   log(`⚠️  ${message}`, colors.yellow);
// }

// function logHeader(message) {
//   log(`\n${colors.bright}${'='.repeat(60)}${colors.reset}`);
//   log(`${colors.bright}${message}${colors.reset}`);
//   log(`${colors.bright}${'='.repeat(60)}${colors.reset}`);
// }

// function logSubHeader(message) {
//   log(`\n${colors.cyan}--- ${message} ---${colors.reset}`);
// }

// // Test scenarios based on account.yaml policy
// const TEST_SCENARIOS = [
//   // READ action tests
//   {
//     name: 'READ Account - Client Role',
//     method: 'GET',
//     endpoint: '/accounts/acc001',
//     user: 'client',
//     expectedStatus: 200,
//     description: 'Client should be able to read account (allowed for client, teller, supervisor, admin)'
//   },
//   {
//     name: 'READ Account - Teller Role',
//     method: 'GET', 
//     endpoint: '/accounts/acc001',
//     user: 'teller',
//     expectedStatus: 200,
//     description: 'Teller should be able to read account'
//   },
//   {
//     name: 'READ Account - Supervisor Role',
//     method: 'GET',
//     endpoint: '/accounts/acc001', 
//     user: 'supervisor',
//     expectedStatus: 200,
//     description: 'Supervisor should be able to read account'
//   },
//   {
//     name: 'READ Account - Admin Role',
//     method: 'GET',
//     endpoint: '/accounts/acc001',
//     user: 'admin',
//     expectedStatus: 200,
//     description: 'Admin should be able to read account'
//   },

//   // UPDATE action tests (only teller, admin allowed)
//   {
//     name: 'UPDATE Account - Client Role (Should Fail)',
//     method: 'PATCH',
//     endpoint: '/accounts/acc001',
//     user: 'client',
//     expectedStatus: 403,
//     description: 'Client should NOT be able to update account (only teller, admin allowed)'
//   },
//   {
//     name: 'UPDATE Account - Teller Role',
//     method: 'PATCH',
//     endpoint: '/accounts/acc001',
//     user: 'teller',
//     expectedStatus: 200,
//     description: 'Teller should be able to update account'
//   },
//   {
//     name: 'UPDATE Account - Admin Role',
//     method: 'PATCH',
//     endpoint: '/accounts/acc001',
//     user: 'admin',
//     expectedStatus: 200,
//     description: 'Admin should be able to update account'
//   },

//   // CREATE action tests (only admin allowed)
//   {
//     name: 'CREATE Account - Client Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/new',
//     user: 'client',
//     expectedStatus: 403,
//     description: 'Client should NOT be able to create account (only admin allowed)'
//   },
//   {
//     name: 'CREATE Account - Teller Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/new',
//     user: 'teller',
//     expectedStatus: 403,
//     description: 'Teller should NOT be able to create account (only admin allowed)'
//   },
//   {
//     name: 'CREATE Account - Admin Role',
//     method: 'POST',
//     endpoint: '/accounts/new',
//     user: 'admin',
//     expectedStatus: 200,
//     description: 'Admin should be able to create account'
//   },

//   // TRANSFER action tests
//   {
//     name: 'TRANSFER - Client with Small Amount (≤ 100M)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'client',
//     data: { amount: 50000000 }, // 50M VND
//     expectedStatus: 200,
//     description: 'Client should be able to transfer amounts ≤ 100M VND'
//   },
//   {
//     name: 'TRANSFER - Client with Large Amount (> 100M) (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'client',
//     data: { amount: 150000000 }, // 150M VND
//     expectedStatus: 403,
//     description: 'Client should NOT be able to transfer amounts > 100M VND'
//   },
//   {
//     name: 'TRANSFER - Client with Exact Limit (100M)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'client',
//     data: { amount: 100000000 }, // 100M VND exactly
//     expectedStatus: 200,
//     description: 'Client should be able to transfer exactly 100M VND'
//   },
//   {
//     name: 'TRANSFER - VIP Client with Large Amount',
//     method: 'POST',
//     endpoint: '/accounts/acc002/transfer',
//     user: 'vip_client',
//     data: { amount: 1500000000 }, // 1.5B VND
//     expectedStatus: 200,
//     description: 'VIP Client should be able to transfer any amount'
//   },
//   {
//     name: 'TRANSFER - Teller Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'teller',
//     data: { amount: 50000000 },
//     expectedStatus: 403,
//     description: 'Teller should NOT be able to transfer (only client roles allowed)'
//   },
//   {
//     name: 'TRANSFER - Admin Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'admin',
//     data: { amount: 50000000 },
//     expectedStatus: 403,
//     description: 'Admin should NOT be able to transfer (only client roles allowed)'
//   },
//   // New test cases for JWT validation
//   {
//     name: 'READ Account - Expired JWT (Should Fail)',
//     method: 'GET',
//     endpoint: '/accounts/acc001',
//     user: 'client',
//     tokenOptions: { expiresIn: '-10s' }, // Token expired 10 seconds ago
//     expectedStatus: 401,
//     description: 'Should fail when using expired JWT token'
//   },
//   {
//     name: 'READ Account - Wrong JWT Secret (MITM) (Should Fail)',
//     method: 'GET',
//     endpoint: '/accounts/acc001',
//     user: 'client',
//     tokenOptions: { secret: WRONG_JWT_SECRET }, // Use wrong secret key
//     expectedStatus: 401,
//     description: 'Should fail when using JWT signed with wrong secret (simulating MITM attack)'
//   }
// ];

// // Execute a single test scenario
// async function runTestScenario(scenario) {
//   logSubHeader(`Testing: ${scenario.name}`);
//   logInfo(`Description: ${scenario.description}`);
  
//   try {
//     const user = TEST_USERS[scenario.user];
//     const token = scenario.tokenOptions 
//       ? generateToken(user, scenario.tokenOptions)
//       : generateToken(user);
    
//     logInfo(`User: ${user.name} (${user.roles.join(', ')})`);
//     logInfo(`Request: ${scenario.method} ${scenario.endpoint}`);
    
//     if (scenario.data) {
//       logInfo(`Data: ${JSON.stringify(scenario.data)}`);
//     }

//     const config = {
//       method: scenario.method,
//       url: `${BASE_URL}${scenario.endpoint}`,
//       headers: {
//         'Authorization': `Bearer ${token}`,
//         'Content-Type': 'application/json'
//       }
//     };

//     if (scenario.data) {
//       config.data = scenario.data;
//     }

//     const response = await axios(config);
    
//     if (response.status === scenario.expectedStatus) {
//       logSuccess(`PASSED - Status: ${response.status}`);
//       logInfo(`Response: ${JSON.stringify(response.data)}`);
//       return { passed: true, scenario: scenario.name };
//     } else {
//       logError(`FAILED - Expected: ${scenario.expectedStatus}, Got: ${response.status}`);
//       logInfo(`Response: ${JSON.stringify(response.data)}`);
//       return { passed: false, scenario: scenario.name, reason: `Status mismatch: ${response.status} != ${scenario.expectedStatus}` };
//     }
    
//   } catch (error) {
//     const status = error.response?.status || 'NO_RESPONSE';
//     const responseData = error.response?.data || error.message;
    
//     if (status === scenario.expectedStatus) {
//       logSuccess(`PASSED - Status: ${status} (Expected failure)`);
//       logInfo(`Response: ${JSON.stringify(responseData)}`);
//       if (responseData.details) {
//         logInfo(`Error Details: ${responseData.details}`);
//       }
//       return { passed: true, scenario: scenario.name };
//     } else {
//       logError(`FAILED - Expected: ${scenario.expectedStatus}, Got: ${status}`);
//       logError(`Error: ${JSON.stringify(responseData)}`);
//       if (responseData.details) {
//         logError(`Error Details: ${responseData.details}`);
//       }
//       return { passed: false, scenario: scenario.name, reason: `Status mismatch: ${status} != ${scenario.expectedStatus}` };
//     }
//   }
// }

// // Run all test scenarios
// async function runAllTests() {
//   logHeader('CERBOS ACCOUNT POLICY TEST SUITE');
//   logInfo('Testing account.yaml policy with all roles and scenarios');
//   logInfo(`Server: ${BASE_URL}`);
  
//   const results = [];
  
//   for (const scenario of TEST_SCENARIOS) {
//     const result = await runTestScenario(scenario);
//     results.push(result);
    
//     // Small delay between tests
//     await new Promise(resolve => setTimeout(resolve, 500));
//   }
  
//   // Summary
//   logHeader('TEST RESULTS SUMMARY');
  
//   const passed = results.filter(r => r.passed).length;
//   const failed = results.filter(r => !r.passed).length;
//   const total = results.length;
  
//   logInfo(`Total Tests: ${total}`);
//   logSuccess(`Passed: ${passed}`);
//   logError(`Failed: ${failed}`);
  
//   if (failed > 0) {
//     logSubHeader('Failed Tests:');
//     results.filter(r => !r.passed).forEach(r => {
//       logError(`- ${r.scenario}: ${r.reason}`);
//     });
//   }
  
//   if (passed === total) {
//     logSuccess('\n🎉 ALL TESTS PASSED! Account policy is working correctly.');
//   } else {
//     logWarning(`\n⚠️  ${failed} test(s) failed. Please check the policy configuration.`);
//   }
// }

// // Run specific test by name
// async function runSpecificTest(testName) {
//   const scenario = TEST_SCENARIOS.find(s => s.name.toLowerCase().includes(testName.toLowerCase()));
  
//   if (!scenario) {
//     logError(`Test not found: ${testName}`);
//     logInfo('Available tests:');
//     TEST_SCENARIOS.forEach(s => logInfo(`- ${s.name}`));
//     return;
//   }
  
//   logHeader(`RUNNING SPECIFIC TEST: ${scenario.name}`);
//   await runTestScenario(scenario);
// }

// // Display available tests
// function listTests() {
//   logHeader('AVAILABLE TEST SCENARIOS');
//   TEST_SCENARIOS.forEach((scenario, index) => {
//     log(`${index + 1}. ${scenario.name}`, colors.cyan);
//     log(`   ${scenario.description}`, colors.white);
//   });
// }

// // Main function
// async function main() {
//   const args = process.argv.slice(2);
  
//   if (args.length === 0) {
//     await runAllTests();
//   } else if (args[0] === 'list') {
//     listTests();
//   } else if (args[0] === 'test') {
//     if (args[1]) {
//       await runSpecificTest(args[1]);
//     } else {
//       logError('Please provide a test name');
//       logInfo('Usage: node test-tool.js test "test-name"');
//     }
//   } else {
//     logInfo('Usage:');
//     logInfo('  node test-tool.js           - Run all tests');
//     logInfo('  node test-tool.js list      - List available tests');
//     logInfo('  node test-tool.js test "name" - Run specific test');
//   }
// }

// // Handle uncaught errors
// process.on('uncaughtException', (error) => {
//   logError(`Uncaught Exception: ${error.message}`);
//   process.exit(1);
// });

// process.on('unhandledRejection', (reason, promise) => {
//   logError(`Unhandled Rejection at: ${promise}, reason: ${reason}`);
//   process.exit(1);
// });

// // Clean up on exit
// process.on('exit', () => {
//   logStream.end();
// });

// // Export for testing
// module.exports = {
//   runAllTests,
//   runSpecificTest,
//   listTests,
//   TEST_SCENARIOS,
//   TEST_USERS
// };

// // Run if called directly
// if (require.main === module) {
//   main().catch(error => {
//     logError(`Error: ${error.message}`);
//     process.exit(1);
//   });
// }

// const jwt = require('jsonwebtoken');
// const axios = require('axios');
// const fs = require('fs');
// const path = require('path');

// // JWT Secret (same as in index.js)
// const JWT_SECRET = 'd1f8a9b3c5e7f2a4d6c8b0e5f3a7d2c1b5e8f3a6d9c2b7e4f1a8d3c6b9e5f2a1';
// const WRONG_JWT_SECRET = 'wrong-secret-key-for-mitm-attack';

// // Base URL for the API
// const BASE_URL = 'http://localhost:3000';

// // Log file setup
// const LOG_FILE = path.join(__dirname, 'cerbos_test.log');
// const logStream = fs.createWriteStream(LOG_FILE, { flags: 'w' });

// // Test users with different roles
// const TEST_USERS = {
//   client: {
//     sub: 'mb000001',
//     name: 'Nguyen Van Anh',
//     roles: ['client'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   },
//   vip_client: {
//     sub: 'mb000002', 
//     name: 'Dao Van Binh',
//     roles: ['vip_client'],
//     account_id: 'acc002',
//     account_type: 'vip'
//   },
//   teller: {
//     sub: 'teller001',
//     name: 'Teller User',
//     roles: ['teller'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   },
//   supervisor: {
//     sub: 'supervisor001',
//     name: 'Supervisor User', 
//     roles: ['supervisor'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   },
//   admin: {
//     sub: 'admin001',
//     name: 'Admin User',
//     roles: ['admin'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   }
// };

// // Generate JWT token for a user
// function generateToken(user, options = {}) {
//   const { secret = JWT_SECRET, expiresIn } = options;
//   const signOptions = { algorithm: 'HS256' };
//   if (expiresIn) {
//     signOptions.expiresIn = expiresIn;
//   }
//   return jwt.sign(user, secret, signOptions);
// }

// // Color codes for console output
// const colors = {
//   reset: '\x1b[0m',
//   bright: '\x1b[1m',
//   red: '\x1b[31m',
//   green: '\x1b[32m',
//   yellow: '\x1b[33m',
//   blue: '\x1b[34m',
//   magenta: '\x1b[35m',
//   cyan: '\x1b[36m',
//   white: '\x1b[37m'
// };

// // Enhanced logging function that writes to both console and file
// function log(message, color = colors.white) {
//   const timestamp = new Date().toISOString();
//   const logMessage = `[${timestamp}] ${message.replace(/\x1b\[\d+m/g, '')}`;
  
//   // Write to file (strip color codes)
//   logStream.write(logMessage + '\n');
  
//   // Write to console with colors
//   console.log(`${color}${message}${colors.reset}`);
// }

// function logSuccess(message) {
//   log(`✅ ${message}`, colors.green);
// }

// function logError(message) {
//   log(`❌ ${message}`, colors.red);
// }

// function logInfo(message) {
//   log(`ℹ️  ${message}`, colors.blue);
// }

// function logWarning(message) {
//   log(`⚠️  ${message}`, colors.yellow);
// }

// function logHeader(message) {
//   log(`\n${colors.bright}${'='.repeat(60)}${colors.reset}`);
//   log(`${colors.bright}${message}${colors.reset}`);
//   log(`${colors.bright}${'='.repeat(60)}${colors.reset}`);
// }

// function logSubHeader(message) {
//   log(`\n${colors.cyan}--- ${message} ---${colors.reset}`);
// }

// // Test scenarios based on account.yaml policy
// const TEST_SCENARIOS = [
//   // READ action tests
//   {
//     name: 'READ Account - Client Role',
//     method: 'GET',
//     endpoint: '/accounts/acc001',
//     user: 'client',
//     expectedStatus: 200,
//     description: 'Client should be able to read account (allowed for client, teller, supervisor, admin)'
//   },
//   {
//     name: 'READ Account - Teller Role',
//     method: 'GET', 
//     endpoint: '/accounts/acc001',
//     user: 'teller',
//     expectedStatus: 200,
//     description: 'Teller should be able to read account'
//   },
//   {
//     name: 'READ Account - Supervisor Role',
//     method: 'GET',
//     endpoint: '/accounts/acc001', 
//     user: 'supervisor',
//     expectedStatus: 200,
//     description: 'Supervisor should be able to read account'
//   },
//   {
//     name: 'READ Account - Admin Role',
//     method: 'GET',
//     endpoint: '/accounts/acc001',
//     user: 'admin',
//     expectedStatus: 200,
//     description: 'Admin should be able to read account'
//   },

//   // UPDATE action tests (only teller, admin allowed)
//   {
//     name: 'UPDATE Account - Client Role (Should Fail)',
//     method: 'PATCH',
//     endpoint: '/accounts/acc001',
//     user: 'client',
//     expectedStatus: 403,
//     description: 'Client should NOT be able to update account (only teller, admin allowed)'
//   },
//   {
//     name: 'UPDATE Account - Teller Role',
//     method: 'PATCH',
//     endpoint: '/accounts/acc001',
//     user: 'teller',
//     expectedStatus: 200,
//     description: 'Teller should be able to update account'
//   },
//   {
//     name: 'UPDATE Account - Admin Role',
//     method: 'PATCH',
//     endpoint: '/accounts/acc001',
//     user: 'admin',
//     expectedStatus: 200,
//     description: 'Admin should be able to update account'
//   },

//   // CREATE action tests (only admin allowed)
//   {
//     name: 'CREATE Account - Client Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/new',
//     user: 'client',
//     expectedStatus: 403,
//     description: 'Client should NOT be able to create account (only admin allowed)'
//   },
//   {
//     name: 'CREATE Account - Teller Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/new',
//     user: 'teller',
//     expectedStatus: 403,
//     description: 'Teller should NOT be able to create account (only admin allowed)'
//   },
//   {
//     name: 'CREATE Account - Admin Role',
//     method: 'POST',
//     endpoint: '/accounts/new',
//     user: 'admin',
//     expectedStatus: 200,
//     description: 'Admin should be able to create account'
//   },

//   // TRANSFER action tests
//   {
//     name: 'TRANSFER - Client with Small Amount (≤ 100M)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'client',
//     data: { amount: 50000000 }, // 50M VND
//     expectedStatus: 200,
//     description: 'Client should be able to transfer amounts ≤ 100M VND'
//   },
//   {
//     name: 'TRANSFER - Client with Large Amount (> 100M) (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'client',
//     data: { amount: 150000000 }, // 150M VND
//     expectedStatus: 403,
//     description: 'Client should NOT be able to transfer amounts > 100M VND'
//   },
//   {
//     name: 'TRANSFER - Client with Exact Limit (100M)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'client',
//     data: { amount: 100000000 }, // 100M VND exactly
//     expectedStatus: 200,
//     description: 'Client should be able to transfer exactly 100M VND'
//   },
//   {
//     name: 'TRANSFER - VIP Client with Large Amount',
//     method: 'POST',
//     endpoint: '/accounts/acc002/transfer',
//     user: 'vip_client',
//     data: { amount: 1500000000 }, // 1.5B VND
//     expectedStatus: 200,
//     description: 'VIP Client should be able to transfer any amount'
//   },
//   {
//     name: 'TRANSFER - Teller Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'teller',
//     data: { amount: 50000000 },
//     expectedStatus: 403,
//     description: 'Teller should NOT be able to transfer (only client roles allowed)'
//   },
//   {
//     name: 'TRANSFER - Admin Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'admin',
//     data: { amount: 50000000 },
//     expectedStatus: 403,
//     description: 'Admin should NOT be able to transfer (only client roles allowed)'
//   },
//   // New test cases for JWT validation
//   {
//     name: 'READ Account - Expired JWT (Should Fail)',
//     method: 'GET',
//     endpoint: '/accounts/acc001',
//     user: 'client',
//     tokenOptions: { expiresIn: '-10s' }, // Token expired 10 seconds ago
//     expectedStatus: 401,
//     description: 'Should fail when using expired JWT token'
//   },
//   {
//     name: 'READ Account - Wrong JWT Secret (MITM) (Should Fail)',
//     method: 'GET',
//     endpoint: '/accounts/acc001',
//     user: 'client',
//     tokenOptions: { secret: WRONG_JWT_SECRET }, // Use wrong secret key
//     expectedStatus: 401,
//     description: 'Should fail when using JWT signed with wrong secret (simulating MITM attack)'
//   }
// ];

// // Execute a single test scenario
// async function runTestScenario(scenario) {
//   logSubHeader(`Testing: ${scenario.name}`);
//   logInfo(`Description: ${scenario.description}`);
  
//   try {
//     const user = TEST_USERS[scenario.user];
//     const token = scenario.tokenOptions 
//       ? generateToken(user, scenario.tokenOptions)
//       : generateToken(user);
    
//     logInfo(`User: ${user.name} (${user.roles.join(', ')})`);
//     logInfo(`Request: ${scenario.method} ${scenario.endpoint}`);
    
//     if (scenario.data) {
//       logInfo(`Data: ${JSON.stringify(scenario.data)}`);
//     }

//     const config = {
//       method: scenario.method,
//       url: `${BASE_URL}${scenario.endpoint}`,
//       headers: {
//         'Authorization': `Bearer ${token}`,
//         'Content-Type': 'application/json'
//       }
//     };

//     if (scenario.data) {
//       config.data = scenario.data;
//     }

//     const response = await axios(config);
    
//     if (response.status === scenario.expectedStatus) {
//       logSuccess(`PASSED - Status: ${response.status}`);
//       logInfo(`Response: ${JSON.stringify(response.data)}`);
//       return { passed: true, scenario: scenario.name };
//     } else {
//       logError(`FAILED - Expected: ${scenario.expectedStatus}, Got: ${response.status}`);
//       logInfo(`Response: ${JSON.stringify(response.data)}`);
//       return { passed: false, scenario: scenario.name, reason: `Status mismatch: ${response.status} != ${scenario.expectedStatus}` };
//     }
    
//   } catch (error) {
//     const status = error.response?.status || 'NO_RESPONSE';
//     const responseData = error.response?.data || error.message;
    
//     if (status === scenario.expectedStatus) {
//       logSuccess(`PASSED - Status: ${status} (Expected failure)`);
//       logInfo(`Response: ${JSON.stringify(responseData)}`);
//       return { passed: true, scenario: scenario.name };
//     } else {
//       logError(`FAILED - Expected: ${scenario.expectedStatus}, Got: ${status}`);
//       logError(`Error: ${JSON.stringify(responseData)}`);
//       return { passed: false, scenario: scenario.name, reason: `Status mismatch: ${status} != ${scenario.expectedStatus}` };
//     }
//   }
// }

// // Run all test scenarios
// async function runAllTests() {
//   logHeader('CERBOS ACCOUNT POLICY TEST SUITE');
//   logInfo('Testing account.yaml policy with all roles and scenarios');
//   logInfo(`Server: ${BASE_URL}`);
  
//   const results = [];
  
//   for (const scenario of TEST_SCENARIOS) {
//     const result = await runTestScenario(scenario);
//     results.push(result);
    
//     // Small delay between tests
//     await new Promise(resolve => setTimeout(resolve, 500));
//   }
  
//   // Summary
//   logHeader('TEST RESULTS SUMMARY');
  
//   const passed = results.filter(r => r.passed).length;
//   const failed = results.filter(r => !r.passed).length;
//   const total = results.length;
  
//   logInfo(`Total Tests: ${total}`);
//   logSuccess(`Passed: ${passed}`);
//   logError(`Failed: ${failed}`);
  
//   if (failed > 0) {
//     logSubHeader('Failed Tests:');
//     results.filter(r => !r.passed).forEach(r => {
//       logError(`- ${r.scenario}: ${r.reason}`);
//     });
//   }
  
//   if (passed === total) {
//     logSuccess('\n🎉 ALL TESTS PASSED! Account policy is working correctly.');
//   } else {
//     logWarning(`\n⚠️  ${failed} test(s) failed. Please check the policy configuration.`);
//   }
// }

// // Run specific test by name
// async function runSpecificTest(testName) {
//   const scenario = TEST_SCENARIOS.find(s => s.name.toLowerCase().includes(testName.toLowerCase()));
  
//   if (!scenario) {
//     logError(`Test not found: ${testName}`);
//     logInfo('Available tests:');
//     TEST_SCENARIOS.forEach(s => logInfo(`- ${s.name}`));
//     return;
//   }
  
//   logHeader(`RUNNING SPECIFIC TEST: ${scenario.name}`);
//   await runTestScenario(scenario);
// }

// // Display available tests
// function listTests() {
//   logHeader('AVAILABLE TEST SCENARIOS');
//   TEST_SCENARIOS.forEach((scenario, index) => {
//     log(`${index + 1}. ${scenario.name}`, colors.cyan);
//     log(`   ${scenario.description}`, colors.white);
//   });
// }

// // Main function
// async function main() {
//   const args = process.argv.slice(2);
  
//   if (args.length === 0) {
//     await runAllTests();
//   } else if (args[0] === 'list') {
//     listTests();
//   } else if (args[0] === 'test') {
//     if (args[1]) {
//       await runSpecificTest(args[1]);
//     } else {
//       logError('Please provide a test name');
//       logInfo('Usage: node test-tool.js test "test-name"');
//     }
//   } else {
//     logInfo('Usage:');
//     logInfo('  node test-tool.js           - Run all tests');
//     logInfo('  node test-tool.js list      - List available tests');
//     logInfo('  node test-tool.js test "name" - Run specific test');
//   }
// }

// // Handle uncaught errors
// process.on('uncaughtException', (error) => {
//   logError(`Uncaught Exception: ${error.message}`);
//   process.exit(1);
// });

// process.on('unhandledRejection', (reason, promise) => {
//   logError(`Unhandled Rejection at: ${promise}, reason: ${reason}`);
//   process.exit(1);
// });

// // Clean up on exit
// process.on('exit', () => {
//   logStream.end();
// });

// // Export for testing
// module.exports = {
//   runAllTests,
//   runSpecificTest,
//   listTests,
//   TEST_SCENARIOS,
//   TEST_USERS
// };

// // Run if called directly
// if (require.main === module) {
//   main().catch(error => {
//     logError(`Error: ${error.message}`);
//     process.exit(1);
//   });
// }



// const jwt = require('jsonwebtoken');
// const axios = require('axios');
// const fs = require('fs');
// const path = require('path');

// // JWT Secret (same as in index.js)
// const JWT_SECRET = 'd1f8a9b3c5e7f2a4d6c8b0e5f3a7d2c1b5e8f3a6d9c2b7e4f1a8d3c6b9e5f2a1';

// // Base URL for the API
// const BASE_URL = 'http://localhost:3000';

// // Log file setup
// const LOG_FILE = path.join(__dirname, 'cerbos_test.log');
// const logStream = fs.createWriteStream(LOG_FILE, { flags: 'w' });

// // Test users with different roles
// const TEST_USERS = {
//   client: {
//     sub: 'mb000001',
//     name: 'Nguyen Van Anh',
//     roles: ['client'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   },
//   vip_client: {
//     sub: 'mb000002', 
//     name: 'Dao Van Binh',
//     roles: ['vip_client'],
//     account_id: 'acc002',
//     account_type: 'vip'
//   },
//   teller: {
//     sub: 'teller001',
//     name: 'Teller User',
//     roles: ['teller'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   },
//   supervisor: {
//     sub: 'supervisor001',
//     name: 'Supervisor User', 
//     roles: ['supervisor'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   },
//   admin: {
//     sub: 'admin001',
//     name: 'Admin User',
//     roles: ['admin'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   }
// };

// // Generate JWT token for a user
// function generateToken(user) {
//   return jwt.sign(user, JWT_SECRET, { algorithm: 'HS256' });
// }

// // Color codes for console output
// const colors = {
//   reset: '\x1b[0m',
//   bright: '\x1b[1m',
//   red: '\x1b[31m',
//   green: '\x1b[32m',
//   yellow: '\x1b[33m',
//   blue: '\x1b[34m',
//   magenta: '\x1b[35m',
//   cyan: '\x1b[36m',
//   white: '\x1b[37m'
// };

// // Enhanced logging function that writes to both console and file
// function log(message, color = colors.white) {
//   const timestamp = new Date().toISOString();
//   const logMessage = `[${timestamp}] ${message.replace(/\x1b\[\d+m/g, '')}`;
  
//   // Write to file (strip color codes)
//   logStream.write(logMessage + '\n');
  
//   // Write to console with colors
//   console.log(`${color}${message}${colors.reset}`);
// }

// function logSuccess(message) {
//   log(`✅ ${message}`, colors.green);
// }

// function logError(message) {
//   log(`❌ ${message}`, colors.red);
// }

// function logInfo(message) {
//   log(`ℹ️  ${message}`, colors.blue);
// }

// function logWarning(message) {
//   log(`⚠️  ${message}`, colors.yellow);
// }

// function logHeader(message) {
//   log(`\n${colors.bright}${'='.repeat(60)}${colors.reset}`);
//   log(`${colors.bright}${message}${colors.reset}`);
//   log(`${colors.bright}${'='.repeat(60)}${colors.reset}`);
// }

// function logSubHeader(message) {
//   log(`\n${colors.cyan}--- ${message} ---${colors.reset}`);
// }

// // Test scenarios based on account.yaml policy
// const TEST_SCENARIOS = [
//   // READ action tests
//   {
//     name: 'READ Account - Client Role',
//     method: 'GET',
//     endpoint: '/accounts/acc001',
//     user: 'client',
//     expectedStatus: 200,
//     description: 'Client should be able to read account (allowed for client, teller, supervisor, admin)'
//   },
//   {
//     name: 'READ Account - Teller Role',
//     method: 'GET', 
//     endpoint: '/accounts/acc001',
//     user: 'teller',
//     expectedStatus: 200,
//     description: 'Teller should be able to read account'
//   },
//   {
//     name: 'READ Account - Supervisor Role',
//     method: 'GET',
//     endpoint: '/accounts/acc001', 
//     user: 'supervisor',
//     expectedStatus: 200,
//     description: 'Supervisor should be able to read account'
//   },
//   {
//     name: 'READ Account - Admin Role',
//     method: 'GET',
//     endpoint: '/accounts/acc001',
//     user: 'admin',
//     expectedStatus: 200,
//     description: 'Admin should be able to read account'
//   },

//   // UPDATE action tests (only teller, admin allowed)
//   {
//     name: 'UPDATE Account - Client Role (Should Fail)',
//     method: 'PATCH',
//     endpoint: '/accounts/acc001',
//     user: 'client',
//     expectedStatus: 403,
//     description: 'Client should NOT be able to update account (only teller, admin allowed)'
//   },
//   {
//     name: 'UPDATE Account - Teller Role',
//     method: 'PATCH',
//     endpoint: '/accounts/acc001',
//     user: 'teller',
//     expectedStatus: 200,
//     description: 'Teller should be able to update account'
//   },
//   {
//     name: 'UPDATE Account - Admin Role',
//     method: 'PATCH',
//     endpoint: '/accounts/acc001',
//     user: 'admin',
//     expectedStatus: 200,
//     description: 'Admin should be able to update account'
//   },

//   // CREATE action tests (only admin allowed)
//   {
//     name: 'CREATE Account - Client Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/new',
//     user: 'client',
//     expectedStatus: 403,
//     description: 'Client should NOT be able to create account (only admin allowed)'
//   },
//   {
//     name: 'CREATE Account - Teller Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/new',
//     user: 'teller',
//     expectedStatus: 403,
//     description: 'Teller should NOT be able to create account (only admin allowed)'
//   },
//   {
//     name: 'CREATE Account - Admin Role',
//     method: 'POST',
//     endpoint: '/accounts/new',
//     user: 'admin',
//     expectedStatus: 200,
//     description: 'Admin should be able to create account'
//   },

//   // TRANSFER action tests
//   {
//     name: 'TRANSFER - Client with Small Amount (≤ 100M)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'client',
//     data: { amount: 50000000 }, // 50M VND
//     expectedStatus: 200,
//     description: 'Client should be able to transfer amounts ≤ 100M VND'
//   },
//   {
//     name: 'TRANSFER - Client with Large Amount (> 100M) (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'client',
//     data: { amount: 150000000 }, // 150M VND
//     expectedStatus: 403,
//     description: 'Client should NOT be able to transfer amounts > 100M VND'
//   },
//   {
//     name: 'TRANSFER - Client with Exact Limit (100M)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'client',
//     data: { amount: 100000000 }, // 100M VND exactly
//     expectedStatus: 200,
//     description: 'Client should be able to transfer exactly 100M VND'
//   },
//   {
//     name: 'TRANSFER - VIP Client with Large Amount',
//     method: 'POST',
//     endpoint: '/accounts/acc002/transfer',
//     user: 'vip_client',
//     data: { amount: 1500000000 }, // 1.5B VND
//     expectedStatus: 200,
//     description: 'VIP Client should be able to transfer any amount'
//   },
//   {
//     name: 'TRANSFER - Teller Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'teller',
//     data: { amount: 50000000 },
//     expectedStatus: 403,
//     description: 'Teller should NOT be able to transfer (only client roles allowed)'
//   },
//   {
//     name: 'TRANSFER - Admin Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'admin',
//     data: { amount: 50000000 },
//     expectedStatus: 403,
//     description: 'Admin should NOT be able to transfer (only client roles allowed)'
//   }
// ];

// // Execute a single test scenario
// async function runTestScenario(scenario) {
//   logSubHeader(`Testing: ${scenario.name}`);
//   logInfo(`Description: ${scenario.description}`);
  
//   try {
//     const user = TEST_USERS[scenario.user];
//     const token = generateToken(user);
    
//     logInfo(`User: ${user.name} (${user.roles.join(', ')})`);
//     logInfo(`Request: ${scenario.method} ${scenario.endpoint}`);
    
//     if (scenario.data) {
//       logInfo(`Data: ${JSON.stringify(scenario.data)}`);
//     }

//     const config = {
//       method: scenario.method,
//       url: `${BASE_URL}${scenario.endpoint}`,
//       headers: {
//         'Authorization': `Bearer ${token}`,
//         'Content-Type': 'application/json'
//       }
//     };

//     if (scenario.data) {
//       config.data = scenario.data;
//     }

//     const response = await axios(config);
    
//     if (response.status === scenario.expectedStatus) {
//       logSuccess(`PASSED - Status: ${response.status}`);
//       logInfo(`Response: ${JSON.stringify(response.data)}`);
//       return { passed: true, scenario: scenario.name };
//     } else {
//       logError(`FAILED - Expected: ${scenario.expectedStatus}, Got: ${response.status}`);
//       logInfo(`Response: ${JSON.stringify(response.data)}`);
//       return { passed: false, scenario: scenario.name, reason: `Status mismatch: ${response.status} != ${scenario.expectedStatus}` };
//     }
    
//   } catch (error) {
//     const status = error.response?.status || 'NO_RESPONSE';
//     const responseData = error.response?.data || error.message;
    
//     if (status === scenario.expectedStatus) {
//       logSuccess(`PASSED - Status: ${status} (Expected failure)`);
//       logInfo(`Response: ${JSON.stringify(responseData)}`);
//       return { passed: true, scenario: scenario.name };
//     } else {
//       logError(`FAILED - Expected: ${scenario.expectedStatus}, Got: ${status}`);
//       logError(`Error: ${JSON.stringify(responseData)}`);
//       return { passed: false, scenario: scenario.name, reason: `Status mismatch: ${status} != ${scenario.expectedStatus}` };
//     }
//   }
// }

// // Run all test scenarios
// async function runAllTests() {
//   logHeader('CERBOS ACCOUNT POLICY TEST SUITE');
//   logInfo('Testing account.yaml policy with all roles and scenarios');
//   logInfo(`Server: ${BASE_URL}`);
  
//   const results = [];
  
//   for (const scenario of TEST_SCENARIOS) {
//     const result = await runTestScenario(scenario);
//     results.push(result);
    
//     // Small delay between tests
//     await new Promise(resolve => setTimeout(resolve, 500));
//   }
  
//   // Summary
//   logHeader('TEST RESULTS SUMMARY');
  
//   const passed = results.filter(r => r.passed).length;
//   const failed = results.filter(r => !r.passed).length;
//   const total = results.length;
  
//   logInfo(`Total Tests: ${total}`);
//   logSuccess(`Passed: ${passed}`);
//   logError(`Failed: ${failed}`);
  
//   if (failed > 0) {
//     logSubHeader('Failed Tests:');
//     results.filter(r => !r.passed).forEach(r => {
//       logError(`- ${r.scenario}: ${r.reason}`);
//     });
//   }
  
//   if (passed === total) {
//     logSuccess('\n🎉 ALL TESTS PASSED! Account policy is working correctly.');
//   } else {
//     logWarning(`\n⚠️  ${failed} test(s) failed. Please check the policy configuration.`);
//   }
// }

// // Run specific test by name
// async function runSpecificTest(testName) {
//   const scenario = TEST_SCENARIOS.find(s => s.name.toLowerCase().includes(testName.toLowerCase()));
  
//   if (!scenario) {
//     logError(`Test not found: ${testName}`);
//     logInfo('Available tests:');
//     TEST_SCENARIOS.forEach(s => logInfo(`- ${s.name}`));
//     return;
//   }
  
//   logHeader(`RUNNING SPECIFIC TEST: ${scenario.name}`);
//   await runTestScenario(scenario);
// }

// // Display available tests
// function listTests() {
//   logHeader('AVAILABLE TEST SCENARIOS');
//   TEST_SCENARIOS.forEach((scenario, index) => {
//     log(`${index + 1}. ${scenario.name}`, colors.cyan);
//     log(`   ${scenario.description}`, colors.white);
//   });
// }

// // Main function
// async function main() {
//   const args = process.argv.slice(2);
  
//   if (args.length === 0) {
//     await runAllTests();
//   } else if (args[0] === 'list') {
//     listTests();
//   } else if (args[0] === 'test') {
//     if (args[1]) {
//       await runSpecificTest(args[1]);
//     } else {
//       logError('Please provide a test name');
//       logInfo('Usage: node test-tool.js test "test-name"');
//     }
//   } else {
//     logInfo('Usage:');
//     logInfo('  node test-tool.js           - Run all tests');
//     logInfo('  node test-tool.js list      - List available tests');
//     logInfo('  node test-tool.js test "name" - Run specific test');
//   }
// }

// // Handle uncaught errors
// process.on('uncaughtException', (error) => {
//   logError(`Uncaught Exception: ${error.message}`);
//   process.exit(1);
// });

// process.on('unhandledRejection', (reason, promise) => {
//   logError(`Unhandled Rejection at: ${promise}, reason: ${reason}`);
//   process.exit(1);
// });

// // Clean up on exit
// process.on('exit', () => {
//   logStream.end();
// });

// // Export for testing
// module.exports = {
//   runAllTests,
//   runSpecificTest,
//   listTests,
//   TEST_SCENARIOS,
//   TEST_USERS
// };

// // Run if called directly
// if (require.main === module) {
//   main().catch(error => {
//     logError(`Error: ${error.message}`);
//     process.exit(1);
//   });
// }
// const jwt = require('jsonwebtoken');
// const axios = require('axios');

// // JWT Secret (same as in index.js)
// const JWT_SECRET = 'd1f8a9b3c5e7f2a4d6c8b0e5f3a7d2c1b5e8f3a6d9c2b7e4f1a8d3c6b9e5f2a1';

// // Base URL for the API
// const BASE_URL = 'http://localhost:3000';

// // Test users with different roles
// const TEST_USERS = {
//   client: {
//     sub: 'mb000001',
//     name: 'Nguyen Van Anh',
//     roles: ['client'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   },
//   vip_client: {
//     sub: 'mb000002', 
//     name: 'Dao Van Binh',
//     roles: ['vip_client'],
//     account_id: 'acc002',
//     account_type: 'vip'
//   },
//   teller: {
//     sub: 'teller001',
//     name: 'Teller User',
//     roles: ['teller'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   },
//   supervisor: {
//     sub: 'supervisor001',
//     name: 'Supervisor User', 
//     roles: ['supervisor'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   },
//   admin: {
//     sub: 'admin001',
//     name: 'Admin User',
//     roles: ['admin'],
//     account_id: 'acc001',
//     account_type: 'normal'
//   }
// };

// // Generate JWT token for a user
// function generateToken(user) {
//   return jwt.sign(user, JWT_SECRET, { algorithm: 'HS256' });
// }

// // Color codes for console output
// const colors = {
//   reset: '\x1b[0m',
//   bright: '\x1b[1m',
//   red: '\x1b[31m',
//   green: '\x1b[32m',
//   yellow: '\x1b[33m',
//   blue: '\x1b[34m',
//   magenta: '\x1b[35m',
//   cyan: '\x1b[36m',
//   white: '\x1b[37m'
// };

// // Logging functions
// function log(message, color = colors.white) {
//   console.log(`${color}${message}${colors.reset}`);
// }

// function logSuccess(message) {
//   log(`✅ ${message}`, colors.green);
// }

// function logError(message) {
//   log(`❌ ${message}`, colors.red);
// }

// function logInfo(message) {
//   log(`ℹ️  ${message}`, colors.blue);
// }

// function logWarning(message) {
//   log(`⚠️  ${message}`, colors.yellow);
// }

// function logHeader(message) {
//   log(`\n${colors.bright}${'='.repeat(60)}${colors.reset}`);
//   log(`${colors.bright}${message}${colors.reset}`);
//   log(`${colors.bright}${'='.repeat(60)}${colors.reset}`);
// }

// function logSubHeader(message) {
//   log(`\n${colors.cyan}--- ${message} ---${colors.reset}`);
// }

// // Test scenarios based on account.yaml policy
// const TEST_SCENARIOS = [
//   // READ action tests
//   {
//     name: 'READ Account - Client Role',
//     method: 'GET',
//     endpoint: '/accounts/acc001',
//     user: 'client',
//     expectedStatus: 200,
//     description: 'Client should be able to read account (allowed for client, teller, supervisor, admin)'
//   },
//   {
//     name: 'READ Account - Teller Role',
//     method: 'GET', 
//     endpoint: '/accounts/acc001',
//     user: 'teller',
//     expectedStatus: 200,
//     description: 'Teller should be able to read account'
//   },
//   {
//     name: 'READ Account - Supervisor Role',
//     method: 'GET',
//     endpoint: '/accounts/acc001', 
//     user: 'supervisor',
//     expectedStatus: 200,
//     description: 'Supervisor should be able to read account'
//   },
//   {
//     name: 'READ Account - Admin Role',
//     method: 'GET',
//     endpoint: '/accounts/acc001',
//     user: 'admin',
//     expectedStatus: 200,
//     description: 'Admin should be able to read account'
//   },

//   // UPDATE action tests (only teller, admin allowed)
//   {
//     name: 'UPDATE Account - Client Role (Should Fail)',
//     method: 'PATCH',
//     endpoint: '/accounts/acc001',
//     user: 'client',
//     expectedStatus: 403,
//     description: 'Client should NOT be able to update account (only teller, admin allowed)'
//   },
//   {
//     name: 'UPDATE Account - Teller Role',
//     method: 'PATCH',
//     endpoint: '/accounts/acc001',
//     user: 'teller',
//     expectedStatus: 200,
//     description: 'Teller should be able to update account'
//   },
//   {
//     name: 'UPDATE Account - Admin Role',
//     method: 'PATCH',
//     endpoint: '/accounts/acc001',
//     user: 'admin',
//     expectedStatus: 200,
//     description: 'Admin should be able to update account'
//   },

//   // CREATE action tests (only admin allowed)
//   {
//     name: 'CREATE Account - Client Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/new',
//     user: 'client',
//     expectedStatus: 403,
//     description: 'Client should NOT be able to create account (only admin allowed)'
//   },
//   {
//     name: 'CREATE Account - Teller Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/new',
//     user: 'teller',
//     expectedStatus: 403,
//     description: 'Teller should NOT be able to create account (only admin allowed)'
//   },
//   {
//     name: 'CREATE Account - Admin Role',
//     method: 'POST',
//     endpoint: '/accounts/new',
//     user: 'admin',
//     expectedStatus: 200,
//     description: 'Admin should be able to create account'
//   },

//   // TRANSFER action tests
//   {
//     name: 'TRANSFER - Client with Small Amount (≤ 100M)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'client',
//     data: { amount: 50000000 }, // 50M VND
//     expectedStatus: 200,
//     description: 'Client should be able to transfer amounts ≤ 100M VND'
//   },
//   {
//     name: 'TRANSFER - Client with Large Amount (> 100M) (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'client',
//     data: { amount: 150000000 }, // 150M VND
//     expectedStatus: 403,
//     description: 'Client should NOT be able to transfer amounts > 100M VND'
//   },
//   {
//     name: 'TRANSFER - Client with Exact Limit (100M)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'client',
//     data: { amount: 100000000 }, // 100M VND exactly
//     expectedStatus: 200,
//     description: 'Client should be able to transfer exactly 100M VND'
//   },
//   {
//     name: 'TRANSFER - VIP Client with Large Amount',
//     method: 'POST',
//     endpoint: '/accounts/acc002/transfer',
//     user: 'vip_client',
//     data: { amount: 1500000000 }, // 1.5B VND
//     expectedStatus: 200,
//     description: 'VIP Client should be able to transfer any amount'
//   },
//   {
//     name: 'TRANSFER - Teller Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'teller',
//     data: { amount: 50000000 },
//     expectedStatus: 403,
//     description: 'Teller should NOT be able to transfer (only client roles allowed)'
//   },
//   {
//     name: 'TRANSFER - Admin Role (Should Fail)',
//     method: 'POST',
//     endpoint: '/accounts/acc001/transfer',
//     user: 'admin',
//     data: { amount: 50000000 },
//     expectedStatus: 403,
//     description: 'Admin should NOT be able to transfer (only client roles allowed)'
//   }
// ];

// // Execute a single test scenario
// async function runTestScenario(scenario) {
//   logSubHeader(`Testing: ${scenario.name}`);
//   logInfo(`Description: ${scenario.description}`);
  
//   try {
//     const user = TEST_USERS[scenario.user];
//     const token = generateToken(user);
    
//     logInfo(`User: ${user.name} (${user.roles.join(', ')})`);
//     logInfo(`Request: ${scenario.method} ${scenario.endpoint}`);
    
//     if (scenario.data) {
//       logInfo(`Data: ${JSON.stringify(scenario.data)}`);
//     }

//     const config = {
//       method: scenario.method,
//       url: `${BASE_URL}${scenario.endpoint}`,
//       headers: {
//         'Authorization': `Bearer ${token}`,
//         'Content-Type': 'application/json'
//       }
//     };

//     if (scenario.data) {
//       config.data = scenario.data;
//     }

//     const response = await axios(config);
    
//     if (response.status === scenario.expectedStatus) {
//       logSuccess(`PASSED - Status: ${response.status}`);
//       logInfo(`Response: ${JSON.stringify(response.data)}`);
//       return { passed: true, scenario: scenario.name };
//     } else {
//       logError(`FAILED - Expected: ${scenario.expectedStatus}, Got: ${response.status}`);
//       logInfo(`Response: ${JSON.stringify(response.data)}`);
//       return { passed: false, scenario: scenario.name, reason: `Status mismatch: ${response.status} != ${scenario.expectedStatus}` };
//     }
    
//   } catch (error) {
//     const status = error.response?.status || 'NO_RESPONSE';
//     const responseData = error.response?.data || error.message;
    
//     if (status === scenario.expectedStatus) {
//       logSuccess(`PASSED - Status: ${status} (Expected failure)`);
//       logInfo(`Response: ${JSON.stringify(responseData)}`);
//       return { passed: true, scenario: scenario.name };
//     } else {
//       logError(`FAILED - Expected: ${scenario.expectedStatus}, Got: ${status}`);
//       logError(`Error: ${JSON.stringify(responseData)}`);
//       return { passed: false, scenario: scenario.name, reason: `Status mismatch: ${status} != ${scenario.expectedStatus}` };
//     }
//   }
// }

// // Run all test scenarios
// async function runAllTests() {
//   logHeader('CERBOS ACCOUNT POLICY TEST SUITE');
//   logInfo('Testing account.yaml policy with all roles and scenarios');
//   logInfo(`Server: ${BASE_URL}`);
  
//   const results = [];
  
//   for (const scenario of TEST_SCENARIOS) {
//     const result = await runTestScenario(scenario);
//     results.push(result);
    
//     // Small delay between tests
//     await new Promise(resolve => setTimeout(resolve, 500));
//   }
  
//   // Summary
//   logHeader('TEST RESULTS SUMMARY');
  
//   const passed = results.filter(r => r.passed).length;
//   const failed = results.filter(r => !r.passed).length;
//   const total = results.length;
  
//   logInfo(`Total Tests: ${total}`);
//   logSuccess(`Passed: ${passed}`);
//   logError(`Failed: ${failed}`);
  
//   if (failed > 0) {
//     logSubHeader('Failed Tests:');
//     results.filter(r => !r.passed).forEach(r => {
//       logError(`- ${r.scenario}: ${r.reason}`);
//     });
//   }
  
//   if (passed === total) {
//     logSuccess('\n🎉 ALL TESTS PASSED! Account policy is working correctly.');
//   } else {
//     logWarning(`\n⚠️  ${failed} test(s) failed. Please check the policy configuration.`);
//   }
// }

// // Run specific test by name
// async function runSpecificTest(testName) {
//   const scenario = TEST_SCENARIOS.find(s => s.name.toLowerCase().includes(testName.toLowerCase()));
  
//   if (!scenario) {
//     logError(`Test not found: ${testName}`);
//     logInfo('Available tests:');
//     TEST_SCENARIOS.forEach(s => logInfo(`- ${s.name}`));
//     return;
//   }
  
//   logHeader(`RUNNING SPECIFIC TEST: ${scenario.name}`);
//   await runTestScenario(scenario);
// }

// // Display available tests
// function listTests() {
//   logHeader('AVAILABLE TEST SCENARIOS');
//   TEST_SCENARIOS.forEach((scenario, index) => {
//     log(`${index + 1}. ${scenario.name}`, colors.cyan);
//     log(`   ${scenario.description}`, colors.white);
//   });
// }

// // Main function
// async function main() {
//   const args = process.argv.slice(2);
  
//   if (args.length === 0) {
//     await runAllTests();
//   } else if (args[0] === 'list') {
//     listTests();
//   } else if (args[0] === 'test') {
//     if (args[1]) {
//       await runSpecificTest(args[1]);
//     } else {
//       logError('Please provide a test name');
//       logInfo('Usage: node test-tool.js test "test-name"');
//     }
//   } else {
//     logInfo('Usage:');
//     logInfo('  node test-tool.js           - Run all tests');
//     logInfo('  node test-tool.js list      - List available tests');
//     logInfo('  node test-tool.js test "name" - Run specific test');
//   }
// }

// // Handle uncaught errors
// process.on('uncaughtException', (error) => {
//   logError(`Uncaught Exception: ${error.message}`);
//   process.exit(1);
// });

// process.on('unhandledRejection', (reason, promise) => {
//   logError(`Unhandled Rejection at: ${promise}, reason: ${reason}`);
//   process.exit(1);
// });

// // Export for testing
// module.exports = {
//   runAllTests,
//   runSpecificTest,
//   listTests,
//   TEST_SCENARIOS,
//   TEST_USERS
// };

// // Run if called directly
// if (require.main === module) {
//   main().catch(error => {
//     logError(`Error: ${error.message}`);
//     process.exit(1);
//   });
// }
