module.exports = {
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/test/setupMocks.js'],
  testPathIgnorePatterns: ['/node_modules/', '/dist/', '/test/e2e/']
};
