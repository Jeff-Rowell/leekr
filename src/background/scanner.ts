import { detectAwsAccessKeys } from './detectors/aws/access_keys/access_keys';
import { Finding, Occurrence } from '../types/findings.types';
import { Findings } from '../models/Findings';

const findings = new Findings();

function broadcastState(payload: Finding[] = findings.getAllFindigns()) {
    chrome.runtime.sendMessage({
        type: 'NEW_FINDINGS',
        payload: payload
    });
}

export async function findSecrets(content: string, url: string): Promise<null> {
    const awsMatches: Set<Occurrence> = await detectAwsAccessKeys(content, url);

    if (awsMatches.size > 0) {
        awsMatches.forEach(occurrence => {
            if (findings.hasFinding(occurrence.fingerprint)) {
                findings.addOccurrence(occurrence)
            } else {
                findings.createFindingFromOccurrence(occurrence);
            }
        });
    }

    // Update the state after scanning
    broadcastState();
    return null;
}
