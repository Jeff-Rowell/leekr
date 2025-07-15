import { Finding, Occurrence } from '../types/findings.types';
import { ConcreteDetectorFactory } from './detectors/DetectorFactory';
import { DetectorFactory } from './detectors/detector.interface';

export async function findSecrets(content: string, url: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const factory: DetectorFactory = new ConcreteDetectorFactory();

    const detectors = factory.createDetectors();
    const detectionPromises = detectors.map(detector => 
        detector.detect(content, url)
    );
    const allMatches = await Promise.all(detectionPromises);

    allMatches.forEach(matches => {
        createFindings(findings, matches);
    });

    return findings;
}

async function createFindings(findings: Finding[], matches: Occurrence[]) {
    if (matches.length > 0) {
        matches.forEach(occurrence => {
            const f: Finding = {
                numOccurrences: 1,
                secretType: occurrence.secretType,
                secretValue: occurrence.secretValue,
                validity: "valid",
                validatedAt: new Date().toISOString(),
                fingerprint: occurrence.fingerprint,
                occurrences: new Set([occurrence]),
                isNew: true,
                discoveredAt: new Date().toISOString()
            }
            findings.push(f);
        });
    }
}