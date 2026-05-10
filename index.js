// index.js
// =============================================
// @roflsec/cverss
// Live CVE Watcher using NVD API
// =============================================

const https = require('https');
const EventEmitter = require('events');

class CVEWatcher extends EventEmitter {

    constructor(options = {}) {
        super();

        this.url =
            options.url ||
            'https://services.nvd.nist.gov/rest/json/cves/2.0';

        this.interval =
            options.interval ||
            5 * 60 * 1000;

        this.minCVSS =
            options.minCVSS || 0;

        this.seenCVEs = new Set();

        this.isFirstRun = true;

        this.maxInitial =
            options.maxInitial || 10;

        this.lastModStartDate = null;
    }

    // =============================================
    // START
    // =============================================

    start() {

        console.log(
            `🚀 @roflsec/cverss démarré → ${this.url}`
        );

        this.checkCVEs();

        this.intervalId = setInterval(
            () => this.checkCVEs(),
            this.interval
        );

        return this;
    }

    // =============================================
    // STOP
    // =============================================

    stop() {

        if (this.intervalId) {
            clearInterval(this.intervalId);

            console.log(
                '⛔ @roflsec/cverss arrêté.'
            );
        }

        return this;
    }

    // =============================================
    // MAIN
    // =============================================

    async checkCVEs() {

        try {

            const url = this.buildURL();

            const data = await this.fetchJSON(url);

            const vulns =
                data.vulnerabilities || [];

            const newCVEs = [];

            const toProcess = this.isFirstRun
                ? vulns.slice(0, this.maxInitial)
                : vulns;

            for (const vuln of toProcess) {

                const cve =
                    this.normalizeCVE(vuln);

                if (!cve?.id)
                    continue;

                if (cve.cvss < this.minCVSS)
                    continue;

                if (
                    this.isFirstRun ||
                    !this.seenCVEs.has(cve.id)
                ) {

                    this.seenCVEs.add(cve.id);

                    newCVEs.push(cve);
                }
            }

            // save checkpoint
            if (newCVEs.length > 0) {
                this.lastModStartDate = newCVEs.reduce((max, c) => c.published > max ? c.published : max, this.lastModStartDate);
            }

            // logs
            if (newCVEs.length > 0) {

                console.log(
                    `🔔 ${newCVEs.length} nouveau${newCVEs.length > 1 ? 'x' : ''} CVE détecté${newCVEs.length > 1 ? 's' : ''} !`
                );

                for (const cve of newCVEs) {

                    this.emit('cve', cve);

                    if (cve.cvss >= 9) {
                        this.emit('critical', cve);
                    }

                    if (
                        cve.summary
                            ?.toLowerCase()
                            ?.includes('remote code execution')
                    ) {
                        this.emit('rce', cve);
                    }
                }

            } else if (!this.isFirstRun) {

                console.log(
                    '✅ Aucun nouveau CVE.'
                );
            }

            this.isFirstRun = false;

        } catch (err) {

            console.error(
                '❌ Erreur @roflsec/cverss:',
                err.message
            );

            this.emit('error', err);
        }
    }

    // =============================================
    // URL BUILDER
    // =============================================

    buildURL() {

        const url = new URL(this.url);

        url.searchParams.set('resultsPerPage', '20');

        const now = new Date();

        // first run: last 24h
        if (!this.lastModStartDate) {

            const yesterday = new Date(
                now.getTime() - 24 * 60 * 60 * 1000
            );

            url.searchParams.set(
                'lastModStartDate',
                yesterday.toISOString()
            );

            url.searchParams.set(
                'lastModEndDate',
                now.toISOString()
            );

            return url.toString();
        }

        // incremental polling window
        url.searchParams.set(
            'lastModStartDate',
            this.lastModStartDate
        );

        url.searchParams.set(
            'lastModEndDate',
            now.toISOString()
        );

        return url.toString();
    }

    // =============================================
    // FETCH
    // =============================================

    fetchJSON(url) {

        return new Promise((resolve, reject) => {

            https.get(url, (res) => {

                let data = '';

                res.on(
                    'data',
                    chunk => data += chunk
                );

                res.on('end', () => {

                    if (res.statusCode !== 200) {
                        return reject(
                            new Error(`HTTP ${res.statusCode}`)
                        );
                    }

                    try {

                        resolve(
                            JSON.parse(data)
                        );

                    } catch (err) {

                        reject(
                            new Error('Invalid JSON')
                        );
                    }
                });

            }).on('error', reject);
        });
    }

    // =============================================
    // NORMALIZER
    // =============================================

    normalizeCVE(vuln) {

        const cve = vuln.cve;

        if (!cve)
            return null;

        const metrics =
            cve.metrics || {};

        const cvssData =
            metrics.cvssMetricV31?.[0]?.cvssData ||
            metrics.cvssMetricV30?.[0]?.cvssData ||
            metrics.cvssMetricV2?.[0]?.cvssData ||
            {};

        return {

            id:
                cve.id,

            summary:
                cve.descriptions?.find(
                    d => d.lang === 'en'
                )?.value || 'No description',

            cvss:
                cvssData.baseScore || 0,

            severity:
                cvssData.baseSeverity || 'UNKNOWN',

            vector:
                cvssData.vectorString || null,

            published:
                cve.published,

            modified:
                cve.lastModified,

            references:
                cve.references?.map(
                    r => r.url
                ) || [],

            weaknesses:
                cve.weaknesses?.flatMap(
                    w => w.description?.map(
                        d => d.value
                    ) || []
                ) || []
        };
    }
}

if (require.main === module) {

    const watcher = new CVEWatcher();

    watcher.on('cve', console.log);

    watcher.start();
}

module.exports = CVEWatcher;