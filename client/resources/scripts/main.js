/**
 * PROJECT TUTWILER - DASHBOARD APPLICATION
 * Cyberbiosecurity Vulnerability Triage System
 */

class DashboardApp {
    constructor() {
        // Update this to match your running port
        this.API_BASE = 'http://localhost:5239/api';
        this.currentPage = 1;
        this.pageSize = 20;
        this.totalCount = 0;
        this.selectedVulnerabilityId = null;
        this.currentFilters = {
            priorityLevel: '',
            daysBack: '',
            searchQuery: ''
        };
        this.searchDebounceTimer = null;
    }

    /**
     * Initialize the dashboard application
     */
    async init() {
        console.log('🚀 Initializing Project Tutwiler Dashboard...');
        
        // Setup event listeners
        this.setupEventListeners();
        
        // Load initial data
        await this.fetchStats();
        await this.fetchVulnerabilities();
        
        console.log('✅ Dashboard initialized successfully');
    }

    /**
     * Setup all event listeners
     */
    setupEventListeners() {
        // Priority filter
        document.getElementById('priorityFilter').addEventListener('change', () => {
            this.currentFilters.priorityLevel = document.getElementById('priorityFilter').value;
            this.currentPage = 1;
            this.applyFilters();
        });

        // Time range filter
        document.getElementById('timeFilter').addEventListener('change', () => {
            this.currentFilters.daysBack = document.getElementById('timeFilter').value;
            this.currentPage = 1;
            this.applyFilters();
        });

        // Search input with debounce
        document.getElementById('searchInput').addEventListener('input', (e) => {
            clearTimeout(this.searchDebounceTimer);
            this.searchDebounceTimer = setTimeout(() => {
                this.currentFilters.searchQuery = e.target.value.trim();
                if (this.currentFilters.searchQuery.length > 0) {
                    this.performSearch();
                } else {
                    this.currentPage = 1;
                    this.fetchVulnerabilities();
                }
            }, 500);
        });

        // Refresh button
        document.getElementById('refreshBtn').addEventListener('click', () => {
            this.refreshData();
        });

        // Retry button
        document.getElementById('retryBtn').addEventListener('click', () => {
            this.fetchVulnerabilities();
        });

        // Pagination buttons
        document.getElementById('prevPageBtn').addEventListener('click', () => {
            if (this.currentPage > 1) {
                this.currentPage--;
                this.fetchVulnerabilities();
            }
        });

        document.getElementById('nextPageBtn').addEventListener('click', () => {
            const totalPages = Math.ceil(this.totalCount / this.pageSize);
            if (this.currentPage < totalPages) {
                this.currentPage++;
                this.fetchVulnerabilities();
            }
        });
    }

    /**
     * Fetch dashboard statistics
     */
    async fetchStats() {
        try {
            const response = await fetch(`${this.API_BASE}/vulnerabilities/stats`);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const stats = await response.json();
            this.updateStatsDisplay(stats);
            
        } catch (error) {
            console.error('Error fetching stats:', error);
            this.updateStatsDisplay(null);
        }
    }

    /**
     * Update statistics display
     */
    updateStatsDisplay(stats) {
        if (!stats) {
            document.getElementById('criticalCount').textContent = '--';
            document.getElementById('highCount').textContent = '--';
            document.getElementById('mediumCount').textContent = '--';
            document.getElementById('lowCount').textContent = '--';
            document.getElementById('totalCount').textContent = '--';
            document.getElementById('exploitedCount').textContent = '--';
            document.getElementById('lastIngestion').textContent = '--';
            document.getElementById('analyzedCount').textContent = '--';
            return;
        }

        // Priority breakdown
        document.getElementById('criticalCount').textContent = stats.priorityBreakdown.critical;
        document.getElementById('highCount').textContent = stats.priorityBreakdown.high;
        document.getElementById('mediumCount').textContent = stats.priorityBreakdown.medium;
        document.getElementById('lowCount').textContent = stats.priorityBreakdown.low;

        // Additional stats
        document.getElementById('totalCount').textContent = stats.totalVulnerabilities.toLocaleString();
        document.getElementById('exploitedCount').textContent = stats.knownExploitedCount.toLocaleString();
        document.getElementById('lastIngestion').textContent = this.formatDate(stats.lastIngestionTime);
        document.getElementById('analyzedCount').textContent = stats.analyzedVulnerabilities.toLocaleString();
    }

    /**
     * Fetch vulnerabilities with current filters
     */
    async fetchVulnerabilities() {
        this.showLoadingState();

        try {
            const skip = (this.currentPage - 1) * this.pageSize;
            let url = `${this.API_BASE}/vulnerabilities?skip=${skip}&take=${this.pageSize}`;

            if (this.currentFilters.priorityLevel) {
                url += `&priorityLevel=${this.currentFilters.priorityLevel}`;
            }

            if (this.currentFilters.daysBack) {
                url += `&daysBack=${this.currentFilters.daysBack}`;
            }

            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            this.totalCount = result.totalCount;
            this.renderVulnerabilityList(result.data);
            this.updatePagination(result.pageCount);
            
        } catch (error) {
            console.error('Error fetching vulnerabilities:', error);
            this.showErrorState(error.message);
        }
    }

    /**
     * Perform search
     */
    async performSearch() {
        if (!this.currentFilters.searchQuery) {
            this.fetchVulnerabilities();
            return;
        }

        this.showLoadingState();

        try {
            const response = await fetch(
                `${this.API_BASE}/vulnerabilities/search?query=${encodeURIComponent(this.currentFilters.searchQuery)}&limit=50`
            );

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            this.totalCount = result.resultCount;
            this.renderVulnerabilityList(result.data);
            
            // Hide pagination during search
            document.getElementById('paginationControls').style.display = 'none';
            
        } catch (error) {
            console.error('Error performing search:', error);
            this.showErrorState(error.message);
        }
    }

    /**
     * Render vulnerability list
     */
    renderVulnerabilityList(vulnerabilities) {
        const listContainer = document.getElementById('vulnerabilityList');
        const resultCount = document.getElementById('resultCount');
        const loadingIndicator = document.getElementById('loadingIndicator');
        const errorState = document.getElementById('errorState');
        const emptyState = document.getElementById('emptyState');

        // Hide states
        loadingIndicator.style.display = 'none';
        errorState.style.display = 'none';
        emptyState.style.display = 'none';

        // Update result count
        resultCount.textContent = `${this.totalCount} results`;

        // Check if empty
        if (!vulnerabilities || vulnerabilities.length === 0) {
            emptyState.style.display = 'flex';
            listContainer.innerHTML = '';
            return;
        }

        // Render cards
        listContainer.innerHTML = vulnerabilities.map(vuln => this.createVulnerabilityCard(vuln)).join('');

        // Add click listeners
        document.querySelectorAll('.vulnerability-card').forEach(card => {
            card.addEventListener('click', () => {
                const vulnId = parseInt(card.dataset.vulnId);
                this.selectVulnerability(vulnId);
            });
        });
    }

    /**
     * Create vulnerability card HTML
     */
    createVulnerabilityCard(vuln) {
        const priorityClass = vuln.isAnalyzed ? `priority-${vuln.priorityLevelString}` : 'priority-unanalyzed';
        const isSelected = vuln.id === this.selectedVulnerabilityId ? 'selected' : '';
        
        return `
            <div class="vulnerability-card ${priorityClass} ${isSelected}" data-vuln-id="${vuln.id}">
                <div class="vuln-header">
                    <div class="vuln-cve">${vuln.cveId}</div>
                    <div class="vuln-badges">
                        ${vuln.isAnalyzed ? 
                            `<span class="badge badge-priority ${vuln.priorityLevelString}">${vuln.priorityLevelString}</span>` :
                            `<span class="badge" style="background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.3); color: #fff;">UNANALYZED</span>`
                        }
                        ${vuln.knownExploited ? 
                            '<span class="badge badge-exploited">EXPLOITED</span>' : 
                            ''
                        }
                    </div>
                </div>
                <div class="vuln-description">${vuln.descriptionPreview}</div>
                <div class="vuln-meta">
                    ${vuln.cvssScore ? 
                        `<div class="vuln-meta-item">
                            <span class="vuln-meta-label">CVSS:</span>
                            <span class="vuln-meta-value">${vuln.cvssScore}</span>
                        </div>` : 
                        ''
                    }
                    ${vuln.compositeScore ? 
                        `<div class="vuln-meta-item">
                            <span class="vuln-meta-label">BIO SCORE:</span>
                            <span class="vuln-meta-value">${vuln.compositeScore}</span>
                        </div>` : 
                        ''
                    }
                    ${vuln.vendorName ? 
                        `<div class="vuln-meta-item">
                            <span class="vuln-meta-label">VENDOR:</span>
                            <span class="vuln-meta-value">${vuln.vendorName}</span>
                        </div>` : 
                        ''
                    }
                    ${vuln.publishedDate ? 
                        `<div class="vuln-meta-item">
                            <span class="vuln-meta-label">PUBLISHED:</span>
                            <span class="vuln-meta-value">${vuln.publishedDateFormatted}</span>
                        </div>` : 
                        ''
                    }
                </div>
            </div>
        `;
    }

    /**
     * Select vulnerability and load details
     */
    async selectVulnerability(vulnId, skipCache = false) {
        // Update selected card
        document.querySelectorAll('.vulnerability-card').forEach(card => {
            card.classList.remove('selected');
        });
        const selectedCard = document.querySelector(`[data-vuln-id="${vulnId}"]`);
        if (selectedCard) {
            selectedCard.classList.add('selected');
        }

        this.selectedVulnerabilityId = vulnId;

        // Fetch full details
        try {
            // Add cache busting if needed
            const url = skipCache 
                ? `${this.API_BASE}/vulnerabilities/${vulnId}?t=${Date.now()}`
                : `${this.API_BASE}/vulnerabilities/${vulnId}`;
            
            const response = await fetch(url, {
                cache: skipCache ? 'no-cache' : 'default',
                headers: skipCache ? { 'Cache-Control': 'no-cache' } : {}
            });
            
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            
            const vuln = await response.json();
            await this.renderDetailPanel(vuln);
            
        } catch (error) {
            console.error('Error fetching vulnerability details:', error);
            this.showDetailError(error.message);
        }
    }

    /**
     * Render detail panel
     */
    async renderDetailPanel(vuln) {
        const detailPanel = document.getElementById('detailPanel');
        
        let html = `
            <div class="detail-header">
                <h3>${vuln.cveId}</h3>
            </div>

            <!-- Vulnerability Info -->
            <div class="detail-section">
                <div class="detail-section-title">VULNERABILITY INFO</div>
                <div class="detail-field">
                    <span class="detail-field-label">CVE ID:</span>
                    <span class="detail-field-value">${vuln.cveId}</span>
                </div>
                <div class="detail-field">
                    <span class="detail-field-label">Published:</span>
                    <span class="detail-field-value">${vuln.publishedDateFormatted}</span>
                </div>
                ${vuln.vendorName ? `
                <div class="detail-field">
                    <span class="detail-field-label">Vendor:</span>
                    <span class="detail-field-value">${vuln.vendorName}</span>
                </div>
                ` : ''}
                ${vuln.cvssScore ? `
                <div class="detail-field">
                    <span class="detail-field-label">CVSS Score:</span>
                    <span class="detail-field-value ${this.getCvssColorClass(vuln.cvssScore)}">${vuln.cvssScore} (${vuln.severityLabel})</span>
                </div>
                ` : ''}
                ${vuln.knownExploited ? `
                <div class="detail-field">
                    <span class="detail-field-label">Status:</span>
                    <span class="detail-field-value text-critical">⚠ KNOWN EXPLOITED</span>
                </div>
                ` : ''}
                <div class="detail-field" style="flex-direction: column; gap: 5px;">
                    <span class="detail-field-label">Description:</span>
                    <span class="detail-field-value" style="font-size: 12px; line-height: 1.6;">${vuln.description}</span>
                </div>
            </div>
        `;

        // Bio Impact Score Section
        if (vuln.bioImpactScore) {
            const score = vuln.bioImpactScore;
            html += `
                <div class="detail-section">
                    <div class="detail-section-title">BIO-IMPACT ANALYSIS</div>
                    <div class="detail-field">
                        <span class="detail-field-label">Priority Level:</span>
                        <span class="detail-field-value">
                            <span class="badge badge-priority ${score.priorityLevelString}">${score.priorityLevelString}</span>
                        </span>
                    </div>
                    <div class="detail-field">
                        <span class="detail-field-label">Composite Score:</span>
                        <span class="detail-field-value ${this.getPriorityColorClass(score.priorityLevelString)}">${score.compositeScore}</span>
                    </div>
                    ${score.affectedBioSectors ? `
                    <div class="detail-field">
                        <span class="detail-field-label">Bio Sectors:</span>
                        <span class="detail-field-value">${score.affectedBioSectors}</span>
                    </div>
                    ` : ''}
                    ${score.bioRelevanceConfidence ? `
                    <div class="detail-field">
                        <span class="detail-field-label">Confidence:</span>
                        <span class="detail-field-value">${(score.bioRelevanceConfidence * 100).toFixed(0)}%</span>
                    </div>
                    ` : ''}

                    <!-- Score Breakdowns -->
                    <div class="score-bar-container">
                        <div class="score-bar-label">
                            <span>Human Safety</span>
                            <span>${score.humanSafetyScore}/100</span>
                        </div>
                        <div class="score-bar">
                            <div class="score-bar-fill" style="width: ${score.humanSafetyScore}%"></div>
                        </div>
                    </div>

                    <div class="score-bar-container">
                        <div class="score-bar-label">
                            <span>Supply Chain</span>
                            <span>${score.supplyChainScore}/100</span>
                        </div>
                        <div class="score-bar">
                            <div class="score-bar-fill" style="width: ${score.supplyChainScore}%"></div>
                        </div>
                    </div>

                    <div class="score-bar-container">
                        <div class="score-bar-label">
                            <span>Exploitability</span>
                            <span>${score.exploitabilityScore}/100</span>
                        </div>
                        <div class="score-bar">
                            <div class="score-bar-fill" style="width: ${score.exploitabilityScore}%"></div>
                        </div>
                    </div>

                    <div class="score-bar-container">
                        <div class="score-bar-label">
                            <span>Patch Availability</span>
                            <span>${score.patchAvailabilityScore}/100</span>
                        </div>
                        <div class="score-bar">
                            <div class="score-bar-fill" style="width: ${score.patchAvailabilityScore}%"></div>
                        </div>
                    </div>
                </div>
            `;
        } else {
            html += `
                <div class="detail-section">
                    <div class="detail-section-title">BIO-IMPACT ANALYSIS</div>
                    <div class="detail-field">
                        <span class="detail-field-value" style="color: var(--medium-yellow);">
                            ⚠ Not yet analyzed
                        </span>
                    </div>
                    <div class="detail-field" style="margin-top: 15px;">
                        <button id="analyzeBtn" class="analyze-btn" onclick="app.triggerAnalysis(${vuln.id})">
                            <span class="btn-icon">🔬</span> ANALYZE NOW
                        </button>
                    </div>
                    <div id="analysisProgress" style="display: none; margin-top: 15px;">
                        <div style="display: flex; align-items: center; gap: 10px; color: var(--cyber-cyan);">
                            <div class="spinner"></div>
                            <span id="analysisStatus">Running AI analysis...</span>
                        </div>
                    </div>
                </div>
            `;
        }

        // Fetch and display recommendations if available
        if (vuln.recommendationCount > 0) {
            try {
                const recsResponse = await fetch(`${this.API_BASE}/recommendations/vulnerability/${vuln.id}`);
                if (recsResponse.ok) {
                    const recsData = await recsResponse.json();
                    html += this.renderRecommendations(recsData.recommendations);
                }
            } catch (error) {
                console.error('Error fetching recommendations:', error);
            }
        }

        detailPanel.innerHTML = html;
    }

    /**
     * Render recommendations section
     */
    renderRecommendations(recommendations) {
        if (!recommendations || recommendations.length === 0) {
            return '';
        }

        let html = `
            <div class="detail-section">
                <div class="detail-section-title">ACTION RECOMMENDATIONS</div>
        `;

        recommendations.forEach(rec => {
            html += `
                <div class="recommendation-item">
                    <div class="recommendation-type">${rec.recommendationType}</div>
                    <div class="recommendation-text">${rec.actionText}</div>
                    ${rec.requiresTier2 ? '<span class="badge badge-exploited" style="margin-top: 8px; display: inline-block;">TIER-2 REQUIRED</span>' : ''}
                </div>
            `;
        });

        html += `</div>`;
        return html;
    }

    /**
     * Show loading state
     */
    showLoadingState() {
        document.getElementById('loadingIndicator').style.display = 'flex';
        document.getElementById('errorState').style.display = 'none';
        document.getElementById('emptyState').style.display = 'none';
        document.getElementById('vulnerabilityList').innerHTML = '';
    }

    /**
     * Show error state
     */
    showErrorState(message) {
        document.getElementById('loadingIndicator').style.display = 'none';
        document.getElementById('errorState').style.display = 'flex';
        document.getElementById('emptyState').style.display = 'none';
        document.getElementById('errorMessage').textContent = message || 'CONNECTION FAILED';
        document.getElementById('vulnerabilityList').innerHTML = '';
    }

    /**
     * Show detail error
     */
    showDetailError(message) {
        const detailPanel = document.getElementById('detailPanel');
        detailPanel.innerHTML = `
            <div class="detail-header">
                <h3>ERROR</h3>
            </div>
            <div class="error-state">
                <div class="error-icon">✕</div>
                <p class="error-message">${message}</p>
            </div>
        `;
    }

    /**
     * Update pagination controls
     */
    updatePagination(totalPages) {
        const paginationControls = document.getElementById('paginationControls');
        const prevBtn = document.getElementById('prevPageBtn');
        const nextBtn = document.getElementById('nextPageBtn');
        const pageInfo = document.getElementById('pageInfo');

        if (this.currentFilters.searchQuery) {
            paginationControls.style.display = 'none';
            return;
        }

        paginationControls.style.display = 'flex';
        pageInfo.textContent = `Page ${this.currentPage} of ${totalPages}`;

        prevBtn.disabled = this.currentPage === 1;
        nextBtn.disabled = this.currentPage >= totalPages;
    }

    /**
     * Apply filters
     */
    async applyFilters() {
        await this.fetchVulnerabilities();
    }

    /**
     * Refresh all data
     */
    async refreshData() {
        const refreshBtn = document.getElementById('refreshBtn');
        refreshBtn.disabled = true;
        refreshBtn.innerHTML = '<span class="btn-icon" style="animation: spin 0.5s linear infinite;">↻</span> REFRESHING...';

        await Promise.all([
            this.fetchStats(),
            this.fetchVulnerabilities()
        ]);

        setTimeout(() => {
            refreshBtn.disabled = false;
            refreshBtn.innerHTML = '<span class="btn-icon">↻</span> REFRESH';
        }, 500);
    }

    /**
     * Trigger AI analysis for a vulnerability
     */
    async triggerAnalysis(vulnId) {
        console.log(`🔬 Triggering analysis for vulnerability ID ${vulnId}`);
        
        const analyzeBtn = document.getElementById('analyzeBtn');
        const progressDiv = document.getElementById('analysisProgress');
        const statusSpan = document.getElementById('analysisStatus');

        try {
            // Disable button and show progress
            if (analyzeBtn) {
                analyzeBtn.disabled = true;
                analyzeBtn.innerHTML = '<span class="btn-icon">⏳</span> ANALYZING...';
            }
            if (progressDiv) {
                progressDiv.style.display = 'block';
            }

            // Step 1: Run AI analysis and scoring
            if (statusSpan) statusSpan.textContent = 'Running AI bio-relevance analysis...';
            
            const analysisResponse = await fetch(`${this.API_BASE}/analysis/vulnerability/${vulnId}`, {
                method: 'POST'
            });

            if (!analysisResponse.ok) {
                const errorData = await analysisResponse.json().catch(() => ({}));
                throw new Error(errorData.message || `Analysis failed with status ${analysisResponse.status}`);
            }

            const analysisResult = await analysisResponse.json();
            console.log('✅ Analysis completed:', analysisResult);

            // Step 2: Generate recommendations
            if (statusSpan) statusSpan.textContent = 'Generating actionable recommendations...';
            
            try {
                const recsResponse = await fetch(`${this.API_BASE}/recommendations/generate/${vulnId}`, {
                    method: 'POST'
                });

                if (recsResponse.ok) {
                    const recsResult = await recsResponse.json();
                    console.log('✅ Recommendations generated:', recsResult);
                } else {
                    console.warn('Recommendations generation failed, but analysis succeeded');
                }
            } catch (recError) {
                console.warn('Recommendations request failed:', recError);
            }

            // Wait for database to commit (longer delay)
            if (statusSpan) statusSpan.textContent = 'Saving to database...';
            await new Promise(resolve => setTimeout(resolve, 1500));

            // Step 3: Refresh stats and list FIRST
            if (statusSpan) statusSpan.textContent = 'Updating dashboard...';
            
            await Promise.all([
                this.fetchStats().catch(e => console.warn('Stats refresh failed:', e)),
                this.fetchVulnerabilities().catch(e => console.warn('List refresh failed:', e))
            ]);

            // Small delay before refreshing detail panel
            await new Promise(resolve => setTimeout(resolve, 500));

            // Step 4: Refresh the detail panel to show new data (force no cache)
            if (statusSpan) statusSpan.textContent = 'Loading analysis results...';
            await this.selectVulnerability(vulnId, true).catch(e => {
                console.warn('Detail refresh failed:', e);
            });

            console.log('🎉 Analysis complete!');

        } catch (error) {
            console.error('Error during analysis:', error);
            
            // Show error in the progress area
            if (progressDiv && statusSpan) {
                statusSpan.innerHTML = `<span style="color: var(--critical-red);">❌ Error: ${error.message}</span>`;
                
                // Re-enable button after error
                setTimeout(() => {
                    if (analyzeBtn) {
                        analyzeBtn.disabled = false;
                        analyzeBtn.innerHTML = '<span class="btn-icon">🔬</span> ANALYZE NOW';
                    }
                    if (progressDiv) {
                        progressDiv.style.display = 'none';
                    }
                }, 3000);
            }
        }
    }

    /**
     * Format date to human-readable string
     */
    formatDate(dateString) {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        if (diffDays < 7) return `${diffDays}d ago`;
        
        return date.toLocaleDateString();
    }

    /**
     * Get priority color class
     */
    getPriorityColorClass(priority) {
        const map = {
            'CRITICAL': 'text-critical',
            'HIGH': 'text-high',
            'MEDIUM': 'text-medium',
            'LOW': 'text-low'
        };
        return map[priority] || '';
    }

    /**
     * Get CVSS color class
     */
    getCvssColorClass(cvss) {
        if (cvss >= 9.0) return 'text-critical';
        if (cvss >= 7.0) return 'text-high';
        if (cvss >= 4.0) return 'text-medium';
        return 'text-low';
    }
}

// Initialize dashboard when DOM is ready
let app; // Global app instance
document.addEventListener('DOMContentLoaded', () => {
    app = new DashboardApp();
    app.init();
});

