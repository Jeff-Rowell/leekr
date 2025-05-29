import { mergeFindings } from './mergeFindings';
import { Finding, Occurrence } from "../../types/findings.types";
import { AWSOccurrence } from "../../types/aws.types";


describe('mergeFindings', () => {
    const createOccurrence = (accountId: string, url: string): AWSOccurrence => ({
        accountId: accountId,
        arn: `arn:aws:iam::${accountId}:user/leekr`,
        filePath: "main.foobar.js",
        fingerprint: "fp1",
        resourceType: "Access Key",
        secretType: "AWS Access & Secret Keys",
        secretValue: {
            match: { access_key_id: "lol", secret_key_id: "wut" }
        },
        sourceContent: {
            content: "foobar",
            contentEndLineNum: 35,
            contentFilename: "App.js",
            contentStartLineNum: 18,
            exactMatchNumbers: [23, 30]
        },
        url: url,
    });

    const createFinding = (fingerprint: string, occurrences: Set<Occurrence>): Finding => ({
        fingerprint: fingerprint,
        numOccurrences: occurrences.size,
        occurrences: occurrences,
        validity: "valid",
        validatedAt: "2025-05-17T18:16:16.870Z",
        secretType: "AWS Access & Secret Keys",
        secretValue: {
            match: { access_key_id: "lol", secret_key_id: "wut" },
            validatedAt: "2025-05-17T18:16:16.870Z",
            validity: "valid"
        }
    });

    test('should merge new findings with empty existing findings', async () => {
        const existingFindings: Finding[] = [];
        const newFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http://localhost:3000/static/js/main.foobar.js")])),
        ];
        const currentUrl = 'https://example.com';

        const result = await mergeFindings(existingFindings, newFindings, currentUrl);

        expect(result).toHaveLength(1);
        expect(result[0].fingerprint).toBe('fp1');
        expect(result[0].occurrences.size).toBe(1);
    });

    test('should add new finding when fingerprint does not exist', async () => {
        const existingFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http://localhost:3000/static/js/main.foobar.js")])),
        ];
        const newFindings: Finding[] = [
            createFinding("fp2", new Set([createOccurrence("654321", "http://localhost:3000/static/js/main.foobar.js")])),
        ];
        const currentUrl = 'https://example.com';

        const result = await mergeFindings(existingFindings, newFindings, currentUrl);

        expect(result).toHaveLength(2);
        expect(result.map(f => f.fingerprint)).toContain('fp1');
        expect(result.map(f => f.fingerprint)).toContain('fp2');
    });

    test('should update existing occurrence when same origin is found', async () => {
        const existingFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http://localhost:3000/static/js/main.foobar.js")])),
        ];
        const newFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http://localhost:3000/static/js/main.foobar.js")])),
        ];
        const currentUrl = 'http://localhost:3000';

        const result = await mergeFindings(existingFindings, newFindings, currentUrl);

        expect(result).toHaveLength(1);
        expect(result[0].fingerprint).toBe('fp1');
        expect(result[0].occurrences.size).toBe(1);

        const occurrence = Array.from(result[0].occurrences)[0];
        expect(occurrence.url).toBe('http://localhost:3000/static/js/main.foobar.js');
        expect(occurrence.filePath).toBe('main.foobar.js');
    });

    test('should add new occurrence when different origin is found', async () => {
        const existingFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http://example.com:3000/static/js/main.foobar.js")])),
        ];
        const newFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http://localhost:3000/static/js/main.foobar.js")])),
        ];
        const currentUrl = 'https://example.com';

        const result = await mergeFindings(existingFindings, newFindings, currentUrl);

        expect(result).toHaveLength(1);
        expect(result[0].fingerprint).toBe('fp1');
        expect(result[0].occurrences.size).toBe(2);
        expect(result[0].numOccurrences).toBe(2);
    });

    test('should handle multiple existing occurrences', async () => {
        const multiOccurrences: Set<Occurrence> = new Set([
            createOccurrence("123456", "http://example.com:3000/static/js1/"), 
            createOccurrence("654321", "http://other.com:3000/static/js2/")])
        const existingFindings: Finding[] = [
            createFinding("fp1", multiOccurrences),
        ];
        const newFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http://example.com:3000/static/js3/")])),
        ];
        const currentUrl = 'https://example.com';

        const result = await mergeFindings(existingFindings, newFindings, currentUrl);

        expect(result).toHaveLength(1);
        expect(result[0].occurrences.size).toBe(2);

        const occurrences = Array.from(result[0].occurrences);
        const exampleOccurrence = occurrences.find(occ => occ.url.includes('example.com'));
        const otherOccurrence = occurrences.find(occ => occ.url.includes('other.com'));

        expect(exampleOccurrence?.url).toBe('http://example.com:3000/static/js3/');
        expect(exampleOccurrence?.filePath).toBe('main.foobar.js');
        expect(otherOccurrence?.url).toBe('http://other.com:3000/static/js2/');
        expect(otherOccurrence?.filePath).toBe('main.foobar.js');
    });

    test('should handle multiple new findings', async () => {
        const existingFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http://localhost:3000/static/js/main.foobar.js")])),
        ];
        const newFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http://localhost:3000/old/js/main.foobar.js")])),
            createFinding("fp2", new Set([createOccurrence("123456", "http://localhost:3000/updated/js/main.foobar.js")])),
        ];
        const currentUrl = 'https://example.com';

        const result = await mergeFindings(existingFindings, newFindings, currentUrl);

        expect(result).toHaveLength(2);

        const fp1Finding = result.find(f => f.fingerprint === 'fp1');
        const fp2Finding = result.find(f => f.fingerprint === 'fp2');

        expect(fp1Finding?.occurrences.size).toBe(1);
        expect(fp2Finding?.occurrences.size).toBe(1);

        const fp1Occurrence = Array.from(fp1Finding!.occurrences)[0];
        expect(fp1Occurrence.url).toBe("http://localhost:3000/old/js/main.foobar.js");
    });

    test('should not mutate original findings arrays', async () => {
        const existingFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http://localhost:3000/static/js/main.foobar.js")])),
        ];
        const newFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http://localhost:3000/static/js/main.foobar.js")])),
        ];
        const currentUrl = 'https://example.com';

        const originalExistingLength = existingFindings.length;
        const originalNewLength = newFindings.length;
        const originalOccurrenceUrl = Array.from(existingFindings[0].occurrences)[0].url;

        await mergeFindings(existingFindings, newFindings, currentUrl);

        expect(existingFindings).toHaveLength(originalExistingLength);
        expect(newFindings).toHaveLength(originalNewLength);
        expect(Array.from(existingFindings[0].occurrences)[0].url).toBe(originalOccurrenceUrl);
    });

    test('should handle invalid URLs gracefully', async () => {
        const existingFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "htt:/lolhuh/js/main.foobar.js")])),
        ];
        const newFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http//lolhuh:3000/static/js/main.foobar.js")])),
        ];
        const currentUrl = 'http://localhost:3000/';

        const result = await mergeFindings(existingFindings, newFindings, currentUrl);

        expect(result).toHaveLength(1);
        expect(result[0].occurrences.size).toBe(2);
    });

    test('should handle empty arrays', async () => {
        const existingFindings: Finding[] = [];
        const newFindings: Finding[] = [];
        const currentUrl = 'https://example.com';

        const result = await mergeFindings(existingFindings, newFindings, currentUrl);

        expect(result).toHaveLength(0);
    });

    test('should handle findings with same fingerprint but no matching origins', async () => {
        const existingFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http://site1.com:3000/static/js/main.foobar.js")])),
        ];
        const newFindings: Finding[] = [
            createFinding("fp1", new Set([createOccurrence("123456", "http://site2.com:3000/static/js/main.foobar.js")])),
        ];
        const currentUrl = 'https://example.com';

        const result = await mergeFindings(existingFindings, newFindings, currentUrl);

        expect(result).toHaveLength(1);
        expect(result[0].fingerprint).toBe('fp1');
        expect(result[0].occurrences.size).toBe(2);
        expect(result[0].numOccurrences).toBe(2);
    });
});