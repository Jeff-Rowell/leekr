import { Occurrence } from '../../types/findings.types';


export interface SecretDetector {
    readonly type: string;
    readonly name: string;
    
    /**
     * Detect secrets in the provided content
     * @param content The content to scan for secrets
     * @param url The URL where the content was found
     * @returns Promise that resolves to array of detected occurrences
     */
    detect(content: string, url: string): Promise<Occurrence[]>;
}


export interface DetectorFactory {
    /**
     * Create all available detectors
     * @returns Array of all available secret detectors
     */
    createDetectors(): SecretDetector[];
    
    /**
     * Create a specific detector by type
     * @param type The detector type to create
     * @returns The detector instance or undefined if type not found
     */
    createDetector(type: string): SecretDetector | undefined;
}

export type Detector = SecretDetector;