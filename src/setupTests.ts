import '@testing-library/jest-dom';

if (typeof globalThis.crypto === 'undefined') {
    globalThis.crypto = {} as Crypto;
}

if (typeof globalThis.crypto.randomUUID !== 'function') {
    (globalThis.crypto as Crypto).randomUUID = (): `${string}-${string}-${string}-${string}-${string}` =>
        'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3) | 0x8;
            return v.toString(16);
        }) as `${string}-${string}-${string}-${string}-${string}`;
}

global.chrome = {
    storage: {
        local: {
            set: jest.fn(),
            get: jest.fn()
        }
    }
} as any;