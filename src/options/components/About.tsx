import { ExternalLink, Github, Shield } from 'lucide-react';
import React, { useEffect, useState } from 'react';

export const AboutTab: React.FC = () => {
    const [version, setVersion] = useState<string>('1.0.0');

    useEffect(() => {
        const fetchVersion = async () => {
            try {
                if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getManifest) {
                    setVersion(chrome.runtime.getManifest().version);
                }

            } catch (error) {
                console.error('Error fetching extension version:', error);
            }
        };

        fetchVersion();
    }, []);

    return (
        <div className="tab-content">
            <section className="about-section">
                <div className="about-content">
                    <div className="about-header">
                        <div></div>
                        <div className="version-badge">v{version}</div>
                    </div>
                    <div className="about-content-header-container">
                        <div className='about-content-header-img'>
                            <img
                                src="icons/leekr.png"
                                alt="Leekr Logo"
                                className="about-logo"
                            />
                        </div>
                        <div className='about-content-header-text'>
                            <p>Leekr <em>passively identifies</em> secrets exposed in <em>client-side JavaScript</em> while you browse the web.</p>
                        </div>
                    </div>
                    <hr></hr>
                    <h3>About</h3>
                    <p>
                        Leekr is an <em>open-source</em>, <em>MIT-licensed</em> browser extension that detects exposed secrets in <em>client-side JavaScript</em>
                        — like API keys, tokens, and cloud service credentials. It's designed to help identify secret leaks in applications even
                        without access to source code, supports custom secret patterns, and performs configurable validity checks for the secrets it finds.
                    </p>

                    <h3>Key Features</h3>
                    <div className="feature-list">
                        <div className="feature-item">
                            <div className="feature-icon">🔍</div>
                            <div className="feature-text">
                                <strong>Passive Detection</strong>
                                <p>Automatically scans JavaScript files while you browse</p>
                            </div>
                        </div>
                        <div className="feature-item">
                            <div className="feature-icon">🔑</div>
                            <div className="feature-text">
                                <strong>Multiple Secret Types</strong>
                                <p>Identifies API keys, tokens, and cloud credentials</p>
                            </div>
                        </div>
                        <div className="feature-item">
                            <div className="feature-icon">⚙️</div>
                            <div className="feature-text">
                                <strong>Customizable</strong>
                                <p>Customize file suffixes and Leekr will listen for those files</p>
                            </div>
                        </div>
                        <div className="feature-item">
                            <div className="feature-icon">✅</div>
                            <div className="feature-text">
                                <strong>Validity Checks</strong>
                                <p>Verifies and only notifies if discovered secrets are valid</p>
                            </div>
                        </div>
                        <div className="feature-item">
                            <div className="feature-icon">🔄</div>
                            <div className="feature-text">
                                <strong>Configuration Sharing</strong>
                                <p>Share your configuration with others or accross devices.</p>
                            </div>
                        </div>
                        <div className="feature-item">
                            <div className="feature-icon">📃</div>
                            <div className="feature-text">
                                <strong>Source Code Attribution</strong>
                                <p>Identifies the exact lines of code that introduced the exposure.</p>
                            </div>
                        </div>
                    </div>

                    <h3>Open Source</h3>
                    <p>
                        Leekr is completely open source under the MIT license. Contributions to the project are welcome!
                        Visit the GitHub repository below to learn more about the project, report issues, or contribute to its development.
                    </p>
                </div>

                <div className="about-footer">
                    <div className="about-links">
                        <a href="https://github.com/Jeff-Rowell/leekr" className="about-link" target="_blank" rel="noopener noreferrer">
                            <Github size={16} />
                            <span>GitHub Repository</span>
                            <ExternalLink size={12} />
                        </a>
                        <a href="https://leekr.org/privacy" className="about-link" target="_blank" rel="noopener noreferrer">
                            <Shield size={16} />
                            <span>Privacy Policy</span>
                            <ExternalLink size={12} />
                        </a>
                    </div>
                    <p className="copyright">© {new Date().getFullYear()} Leekr</p>
                </div>
            </section>
        </div>
    );
};