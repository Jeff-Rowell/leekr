import type { Config } from 'jest';

const config: Config = {
    transform: {
        '^.+\\.(ts|tsx|js|jsx)$': 'ts-jest',
    },
    testEnvironment: 'jsdom',
    setupFilesAfterEnv: ['<rootDir>/setupTests.ts'],
    testMatch: ['<rootDir>/**/*.test.{ts,tsx}'],
    moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
    moduleNameMapper: {
        "\\.(css)$": "<rootDir>/__mocks__/styleMock.js",
        '\\.(svg|png)$': 'jest-transform-stub',
    },
};

export default config;
