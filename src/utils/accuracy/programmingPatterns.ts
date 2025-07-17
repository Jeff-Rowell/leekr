export const COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS = [
    // PascalCase: starts with capital, followed by lowercase, then more capital+lowercase groups
    // Examples: DisableSnapshotBlockPublicAccess, EnableNetworkAddressUsageMetrics
    /^[A-Z][a-z]+([A-Z][a-z]+)+$/,
    
    // camelCase: starts with lowercase, then capital+lowercase groups  
    // Examples: getUserAccountInfo, processDataStreamBuffer
    /^[a-z]+([A-Z][a-z]+)+$/,
    
    // Mixed case with acronyms: mixed case with 3+ consecutive capitals (not all caps)
    // Examples: setHTTPSProxy, enableJSONParser, parseXMLDocument
    /^[a-z]+[A-Z]{3,}[A-Za-z]+$|^[A-Z][a-z]+[A-Z]{3,}[A-Za-z]*$/,
    
    // Common programming patterns with obvious version numbers or IDs
    // Examples: module1Parser, handler2Buffer, service3Config
    /^[A-Za-z]+\d{1,3}[A-Za-z]+$/,
    
    // Constants with underscores: ALL_CAPS_WITH_UNDERSCORES (minimum 2 parts, each at least 2 chars)
    // Examples: MAX_BUFFER_SIZE, DEFAULT_TIMEOUT_MS
    /^[A-Z]{2,}(_[A-Z]{2,})+$/,
    
    // snake_case: lowercase with underscores (minimum 2 parts, each at least 2 chars)
    // Examples: user_account_info, data_stream_buffer
    /^[a-z]{2,}(_[a-z]{2,})+$/,
    
    // SCREAMING_SNAKE_CASE with numbers (minimum 2 chars per part, except numbers can be 1+ chars)
    // Examples: CONFIG_VERSION_1, BUFFER_SIZE_MAX
    /^[A-Z]{2,}(_[A-Z]{2,}|_[A-Z]*\d+[A-Z]*)+$/,
    
    // Mixed case with common programming suffixes (minimum 8 chars total)
    // Examples: DataBuffer, ConfigParser, StreamHandler
    /^[A-Z][a-z]{2,}(Buffer|Parser|Handler|Manager|Service|Config|Helper|Util|Utils|Factory|Builder|Provider|Controller|Processor|Generator|Validator|Converter|Transformer|Formatter|Scanner|Monitor|Logger|Writer|Reader)$/i,
    
    // Common programming prefixes (minimum 8 chars total)
    // Examples: getAccountInfo, setBufferSize, isValidConfig
    /^(get|set|is|has|can|should|will|did|create|update|delete|add|remove|find|search|filter|sort|parse|format|validate|process|handle|manage|execute|run|start|stop|init|destroy)[A-Z][a-z]{2,}.*$/,
    
    // File extensions and paths (only if they clearly contain file extensions)
    // Examples: configjsonparser, indexhtmlbuffer (must have at least 3 chars before extension)
    /^[a-z]{3,}(html|json|xml|css|jsx|tsx|php|java|cpp|hpp|swift|scala|yaml|toml|conf|properties)[a-z]+$/i,
    
    // AWS/Header/Configuration patterns with dashes - specific keywords
    // Examples: amz-fwd-header-x-amz-server-side-encryption-bucket, x-forwarded-for-header
    /^(amz|aws|fwd|header|x)(-[a-z0-9]+){3,}-?$/,
    
    // Long dash-separated patterns (5+ parts, letters only to avoid API keys)
    // Examples: header-x-amz-server-side-encryption-customer
    /^[a-z]+(-[a-z]+){4,}-?$/
];

export function isProgrammingPattern(text: string): boolean {
    return COMMON_PROGRAMMING_FALSE_POSITIVE_PATTERNS.some(pattern => pattern.test(text));
}

export function filterProgrammingPatterns<T>(
    items: T[], 
    textExtractor: (item: T) => string
): T[] {
    return items.filter(item => {
        const text = textExtractor(item);
        return !isProgrammingPattern(text);
    });
}