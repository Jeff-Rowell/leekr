import { isProgrammingPattern, filterProgrammingPatterns, COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS } from './programmingPatterns';

describe('programmingPatterns', () => {
    describe('isProgrammingPattern', () => {
        test('should detect PascalCase patterns', () => {
            expect(isProgrammingPattern('DisableSnapshotBlockPublicAccess')).toBe(true);
            expect(isProgrammingPattern('EnableNetworkAddressUsageMetrics')).toBe(true);
            expect(isProgrammingPattern('GetReservedNodeExchangeOfferings')).toBe(true);
            expect(isProgrammingPattern('CreateUserAccountManager')).toBe(true);
            expect(isProgrammingPattern('ProcessDataStreamBuffer')).toBe(true);
        });

        test('should detect camelCase patterns', () => {
            expect(isProgrammingPattern('getUserAccountInfo')).toBe(true);
            expect(isProgrammingPattern('processDataStreamBuffer')).toBe(true);
            expect(isProgrammingPattern('enableNetworkConfiguration')).toBe(true);
            expect(isProgrammingPattern('createDatabaseConnection')).toBe(true);
            expect(isProgrammingPattern('validateUserInputData')).toBe(true);
        });

        test('should detect mixed case with acronyms', () => {
            expect(isProgrammingPattern('setHTTPSProxy')).toBe(true);
            expect(isProgrammingPattern('enableJSONParser')).toBe(true);
            expect(isProgrammingPattern('parseXMLDocument')).toBe(true);
            expect(isProgrammingPattern('configAPIEndpoint')).toBe(true);
            expect(isProgrammingPattern('processHTMLContent')).toBe(true);
        });

        test('should detect version/ID patterns', () => {
            expect(isProgrammingPattern('module1Parser')).toBe(true);
            expect(isProgrammingPattern('handler2Buffer')).toBe(true);
            expect(isProgrammingPattern('service3Config')).toBe(true);
            expect(isProgrammingPattern('version12Handler')).toBe(true);
            expect(isProgrammingPattern('config999Manager')).toBe(true);
        });

        test('should detect SCREAMING_SNAKE_CASE patterns', () => {
            expect(isProgrammingPattern('MAX_BUFFER_SIZE')).toBe(true);
            expect(isProgrammingPattern('DEFAULT_TIMEOUT_MS')).toBe(true);
            expect(isProgrammingPattern('CONFIG_VERSION_1')).toBe(true);
            expect(isProgrammingPattern('DATABASE_CONNECTION_URL')).toBe(true);
            expect(isProgrammingPattern('API_RATE_LIMIT_MAX')).toBe(true);
        });

        test('should detect snake_case patterns', () => {
            expect(isProgrammingPattern('user_account_info')).toBe(true);
            expect(isProgrammingPattern('data_stream_buffer')).toBe(true);
            expect(isProgrammingPattern('config_parser_module')).toBe(true);
            expect(isProgrammingPattern('database_connection_pool')).toBe(true);
            expect(isProgrammingPattern('api_response_handler')).toBe(true);
        });

        test('should detect common programming suffixes', () => {
            expect(isProgrammingPattern('DataBuffer')).toBe(true);
            expect(isProgrammingPattern('ConfigParser')).toBe(true);
            expect(isProgrammingPattern('StreamHandler')).toBe(true);
            expect(isProgrammingPattern('UserManager')).toBe(true);
            expect(isProgrammingPattern('ApiService')).toBe(true);
            expect(isProgrammingPattern('DatabaseHelper')).toBe(true);
            expect(isProgrammingPattern('FileValidator')).toBe(true);
            expect(isProgrammingPattern('DataProcessor')).toBe(true);
        });

        test('should detect common programming prefixes', () => {
            expect(isProgrammingPattern('getAccountInfo')).toBe(true);
            expect(isProgrammingPattern('setBufferSize')).toBe(true);
            expect(isProgrammingPattern('isValidConfig')).toBe(true);
            expect(isProgrammingPattern('hasPermission')).toBe(true);
            expect(isProgrammingPattern('canAccessDatabase')).toBe(true);
            expect(isProgrammingPattern('createNewUser')).toBe(true);
            expect(isProgrammingPattern('updateUserData')).toBe(true);
            expect(isProgrammingPattern('deleteOldFiles')).toBe(true);
        });

        test('should detect file extension patterns', () => {
            expect(isProgrammingPattern('configjsonparser')).toBe(true);
            expect(isProgrammingPattern('indexhtmlbuffer')).toBe(true);
            expect(isProgrammingPattern('stylecsshandler')).toBe(true);
            expect(isProgrammingPattern('dataxmlprocessor')).toBe(true);
            expect(isProgrammingPattern('templatehtmlrenderer')).toBe(true);
        });

        test('should not detect random strings', () => {
            expect(isProgrammingPattern('randomstring123456')).toBe(false);
            expect(isProgrammingPattern('abcdef1234567890')).toBe(false);
            expect(isProgrammingPattern('XKCD2023COMIC1234')).toBe(false);
            expect(isProgrammingPattern('secretkey98765432')).toBe(false);
            expect(isProgrammingPattern('token_auth_12345')).toBe(false);
        });

        test('should not detect actual API keys', () => {
            expect(isProgrammingPattern('sk-proj-abc123def456')).toBe(false);
            expect(isProgrammingPattern('ghp_1234567890abcdef')).toBe(false);
            expect(isProgrammingPattern('xoxb-12345-67890-abcdef')).toBe(false);
            expect(isProgrammingPattern('AIzaSyAbCdEf123456')).toBe(false);
            expect(isProgrammingPattern('ya29.abc123def456')).toBe(false);
        });

        test('should not detect short strings', () => {
            expect(isProgrammingPattern('get')).toBe(false);
            expect(isProgrammingPattern('set')).toBe(false);
            expect(isProgrammingPattern('is')).toBe(false);
            expect(isProgrammingPattern('API')).toBe(false);
            expect(isProgrammingPattern('JSON')).toBe(false);
        });

        test('should not detect single case strings', () => {
            expect(isProgrammingPattern('alllowercase')).toBe(false);
            expect(isProgrammingPattern('ALLUPPERCASE')).toBe(false);
            expect(isProgrammingPattern('1234567890')).toBe(false);
            expect(isProgrammingPattern('simple')).toBe(false);
            expect(isProgrammingPattern('SIMPLE')).toBe(false);
        });
    });

    describe('filterProgrammingPatterns', () => {
        test('should filter out programming patterns from array of strings', () => {
            const testStrings = [
                'DisableSnapshotBlockPublicAccess',
                'sk-proj-abc123def456',
                'getUserAccountInfo',
                'ghp_1234567890abcdef',
                'MAX_BUFFER_SIZE',
                'randomstring123456'
            ];

            const filtered = filterProgrammingPatterns(testStrings, str => str);

            expect(filtered).toEqual([
                'sk-proj-abc123def456',
                'ghp_1234567890abcdef',
                'randomstring123456'
            ]);
        });

        test('should filter programming patterns from array of objects', () => {
            const testObjects = [
                { key: 'DisableSnapshotBlockPublicAccess', value: 'test1' },
                { key: 'sk-proj-abc123def456', value: 'test2' },
                { key: 'getUserAccountInfo', value: 'test3' },
                { key: 'randomstring123456', value: 'test4' }
            ];

            const filtered = filterProgrammingPatterns(testObjects, obj => obj.key);

            expect(filtered).toEqual([
                { key: 'sk-proj-abc123def456', value: 'test2' },
                { key: 'randomstring123456', value: 'test4' }
            ]);
        });

        test('should return empty array when all items match programming patterns', () => {
            const programmingStrings = [
                'DisableSnapshotBlockPublicAccess',
                'getUserAccountInfo',
                'MAX_BUFFER_SIZE',
                'DataBuffer'
            ];

            const filtered = filterProgrammingPatterns(programmingStrings, str => str);

            expect(filtered).toEqual([]);
        });

        test('should return all items when none match programming patterns', () => {
            const nonProgrammingStrings = [
                'sk-proj-abc123def456',
                'ghp_1234567890abcdef',
                'randomstring123456',
                'secretkey98765432'
            ];

            const filtered = filterProgrammingPatterns(nonProgrammingStrings, str => str);

            expect(filtered).toEqual(nonProgrammingStrings);
        });
    });

    describe('COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS', () => {
        test('should export an array of RegExp patterns', () => {
            expect(Array.isArray(COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS)).toBe(true);
            expect(COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS.length).toBeGreaterThan(0);
            
            COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS.forEach(pattern => {
                expect(pattern).toBeInstanceOf(RegExp);
            });
        });

        test('should have unique patterns', () => {
            const patternStrings = COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS.map(p => p.toString());
            const uniquePatterns = new Set(patternStrings);
            
            expect(uniquePatterns.size).toBe(COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS.length);
        });
    });
});